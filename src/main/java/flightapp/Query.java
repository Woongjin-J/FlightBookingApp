package flightapp;

import java.io.*;
import java.sql.*;
import java.util.*;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.xml.transform.Result;

/**
 * Runs queries against a back-end database
 */
public class Query {
  // DB Connection
  private Connection conn;

  // Password hashing parameter constants
  private static final int HASH_STRENGTH = 65536;
  private static final int KEY_LENGTH = 128;

  // Canned queries
  private static final String CHECK_FLIGHT_CAPACITY = "SELECT capacity FROM Flights WHERE fid = ?";
  private PreparedStatement checkFlightCapacityStatement;

  // For check dangling
  private static final String TRANCOUNT_SQL = "SELECT @@TRANCOUNT AS tran_count";
  private PreparedStatement tranCountStatement;

  // beginTransaction, commit and rollback
  private static final String BEGIN_TRAN_SQL = "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE; BEGIN TRANSACTION;";
  private PreparedStatement beginTranStatement;
  private static final String COMMIT_SQL = "COMMIT TRANSACTION";
  private PreparedStatement commitStatement;
  private static final String ROLLBACK_SQL = "ROLLBACK TRANSACTION";
  private PreparedStatement rollbackStatement;

  // clear -- for clear User and Reservation tables: clearTables()
  private static final String CLEAR_USER_TABLE = "DELETE FROM Users";
  private PreparedStatement clearUserTableStatement;
  private static final String CLEAR_RES_TABLE = "DELETE FROM Reservations";
  private PreparedStatement clearResTableStatement;

  // create
  private static final String CREATE_USER = "INSERT INTO Users values (?, ?, ?, ?)";
  private PreparedStatement createUserStatement;

  // log in
  private String loginUser = null;
  private static final String LOG_IN = "SELECT salt, password FROM Users WHERE username = ? ";
  private PreparedStatement logInUserStatement;

  // direct search
  private static final String DIRECT_SEARCH = "SELECT TOP (?) fid, day_of_month, carrier_id, flight_num,origin_city,"+
          " dest_city, actual_time, capacity, price "+"FROM Flights WHERE origin_city = ? AND dest_city = ? "+
          "AND day_of_month = ? and canceled = 0 ORDER BY actual_time, fid ASC";
  private PreparedStatement directSearchStatement;

  // one hop search
  private static final String ONE_HOP_SEARCH =  "SELECT TOP (?) F1.fid as F1_fid, F1.day_of_month as F1_dom, "+
          "F1.carrier_id as F1_cid, F1.flight_num as F1_fn, F1.origin_city as F1_oc, F1.dest_city as F1_dc, "+
          "F1.actual_time as F1_time, F1.capacity as F1_cap, F1.price as F1_price, "+
          "F2.fid as F2_fid, F2.day_of_month as F2_dom, "+
          "F2.carrier_id as F2_cid, F2.flight_num as F2_fn, F2.origin_city as F2_oc, F2.dest_city as F2_dc, "+
          "F2.actual_time as F2_time, F2.capacity as F2_cap,  F2.price as F2_price "+
          "FROM Flights as F1, Flights as F2 "+
          "WHERE F1.dest_city = F2.origin_city "+
          "AND F1.origin_city = ? and F1.dest_city <> ? and F2.dest_city = ? "+
          "AND F1.canceled = 0 and F2.canceled = 0 "+
          "AND F1.day_of_month = ? and F2.day_of_month = ? "+
          "ORDER BY (F1.actual_time+F2.actual_time), F1.fid, F2.fid ASC";
  private PreparedStatement oneHopSearchStatement;

  // book - searchReturnedFlights key -- itineraryId, val : List<Flight> 看情况可以改成concurrentHashMap
  private Map<Integer, List<Flight>> searchReturnedFlights = new HashMap<>();

  private static final String CHECK_DEFAULT_CAP = "SELECT capacity from Flights WHERE fid = ?";
  private PreparedStatement checkDefaultCapStatement;
  private static final String CHECK_RES_CAP = "SELECT count(*) AS cnt from Reservations WHERE (f1_id = ? AND canceled = 0) OR (f2_id = ? AND canceled = 0)";
  private PreparedStatement checkReserveCapStatement;
  private static final String GET_USER_RES_OF_THE_DAY = "SELECT count(*) AS cnt FROM Reservations WHERE username = ? AND day_of_month = ? AND canceled = 0";
  private PreparedStatement getUserResOfTheDayStatement;
  private static final String CHECK_RESERVATION_SIZE = "SELECT count(*) AS cnt FROM Reservations";
  private PreparedStatement checkReservationSizeStatement;
  private static final String CREATE_RESERVATION = "INSERT INTO Reservations VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
  private PreparedStatement createReservationStatement;

  // reservation
  private static final String CHECK_RESERVATION = "SELECT res_id, f1_id, f2_id, paid FROM Reservations WHERE username = ? AND canceled = 0";
  private PreparedStatement checkReservationStatement;
  private static final String GET_FLIGHT = "SELECT day_of_month, carrier_id, flight_num, origin_city, dest_city, actual_time, capacity, price FROM Flights WHERE fid = ? ";
  private PreparedStatement getFlightStatement;

  // pay
  private static final String GET_USER = "SELECT u.username as username, u.initAmount as initAmount, price, paid FROM Users as u, Reservations as r WHERE r.res_id = ? AND u.username = ? AND r.username = u.username AND r.canceled = 0";
  private PreparedStatement getUserInfoStatement;
  private static final String REFUND = "UPDATE Users SET initAmount = ? WHERE username = ? ";
  private PreparedStatement refundStatement;
  private static final String UPDATE_RESERVATION = "UPDATE Reservations SET paid = ? WHERE res_id = ?";
  private PreparedStatement updateReservStatement;

  // cancel
  private static final String CANCEL_RESERVATION = "UPDATE Reservations SET canceled = 1 WHERE res_id = ? ";
  private PreparedStatement cancelReservationStatement;
  private static final String MAKE_UNPAID = "UPDATE Reservations SET paid = 0 WHERE username = ? ";
  private PreparedStatement makeUnpaidStatement;

  public Query() throws SQLException, IOException {
    this(null, null, null, null);
  }

  protected Query(String serverURL, String dbName, String adminName, String password)
          throws SQLException, IOException {
    conn = serverURL == null ? openConnectionFromDbConn()
            : openConnectionFromCredential(serverURL, dbName, adminName, password);

    prepareStatements();
  }

  /**
   * Return a connecion by using dbconn.properties file
   *
   * @throws SQLException
   * @throws IOException
   */
  public static Connection openConnectionFromDbConn() throws SQLException, IOException {
    // Connect to the database with the provided connection configuration
    Properties configProps = new Properties();
    configProps.load(new FileInputStream("dbconn.properties"));
    String serverURL = configProps.getProperty("flightapp.server_url");
    String dbName = configProps.getProperty("flightapp.database_name");
    String adminName = configProps.getProperty("flightapp.username");
    String password = configProps.getProperty("flightapp.password");
    return openConnectionFromCredential(serverURL, dbName, adminName, password);
  }

  /**
   * Return a connecion by using the provided parameter.
   *
   * @param serverURL example: example.database.widows.net
   * @param dbName    database name
   * @param adminName username to login server
   * @param password  password to login server
   *
   * @throws SQLException
   */
  protected static Connection openConnectionFromCredential(String serverURL, String dbName,
                                                           String adminName, String password) throws SQLException {
    String connectionUrl =
            String.format("jdbc:sqlserver://%s:1433;databaseName=%s;user=%s;password=%s", serverURL,
                    dbName, adminName, password);
    Connection conn = DriverManager.getConnection(connectionUrl);

    // By default, automatically commit after each statement
    conn.setAutoCommit(true);

    // By default, set the transaction isolation level to serializable
    conn.setTransactionIsolation(Connection.TRANSACTION_SERIALIZABLE);

    return conn;
  }

  /**
   * Get underlying connection
   */
  public Connection getConnection() {
    return conn;
  }

  /**
   * Closes the application-to-database connection
   */
  public void closeConnection() throws SQLException {
    conn.close();
  }

  /**
   * Clear the data in any custom tables created.
   *
   * WARNING! Do not drop any tables and do not clear the flights table.
   */
  public void clearTables() {
    try {
      clearResTableStatement.clearParameters();
      clearResTableStatement.executeUpdate();
      clearUserTableStatement.clearParameters();
      clearUserTableStatement.executeUpdate();
    } catch (Exception e) {
      e.printStackTrace();
    }
  }

  /**
   * prepare all the SQL statements in this method.
   */
  private void prepareStatements() throws SQLException {
    checkFlightCapacityStatement = conn.prepareStatement(CHECK_FLIGHT_CAPACITY);
    tranCountStatement = conn.prepareStatement(TRANCOUNT_SQL);
    // beginTransaction, commit, rollback
    beginTranStatement = conn.prepareStatement(BEGIN_TRAN_SQL);
    commitStatement = conn.prepareStatement(COMMIT_SQL);
    rollbackStatement = conn.prepareStatement(ROLLBACK_SQL);
    // clearTables
    clearUserTableStatement = conn.prepareStatement(CLEAR_USER_TABLE);
    clearResTableStatement = conn.prepareStatement(CLEAR_RES_TABLE);
    // create
    createUserStatement = conn.prepareStatement(CREATE_USER);
    // login
    logInUserStatement = conn.prepareStatement(LOG_IN);
    // search
    directSearchStatement = conn.prepareStatement(DIRECT_SEARCH);
    oneHopSearchStatement = conn.prepareStatement(ONE_HOP_SEARCH);
    // book
    checkDefaultCapStatement = conn.prepareStatement(CHECK_DEFAULT_CAP);
    checkReserveCapStatement = conn.prepareStatement(CHECK_RES_CAP);

    getUserResOfTheDayStatement = conn.prepareStatement(GET_USER_RES_OF_THE_DAY);
    checkReservationSizeStatement = conn.prepareStatement(CHECK_RESERVATION_SIZE);
    createReservationStatement = conn.prepareStatement(CREATE_RESERVATION);
    // reservation
    checkReservationStatement = conn.prepareStatement(CHECK_RESERVATION);
    getFlightStatement = conn.prepareStatement(GET_FLIGHT);
    // pay
    getUserInfoStatement = conn.prepareStatement(GET_USER);
    //updateUserStatement = conn.prepareStatement(UPDATE_USER);
    updateReservStatement = conn.prepareStatement(UPDATE_RESERVATION);
    // cancel
    cancelReservationStatement = conn.prepareStatement(CANCEL_RESERVATION);
    refundStatement = conn.prepareStatement(REFUND);
    makeUnpaidStatement = conn.prepareStatement(MAKE_UNPAID);
  }

  private void rollBack_create() {
    try {
      rollbackStatement.execute();
      conn.setAutoCommit(true);
      createUserStatement.clearParameters();
    } catch (SQLException e) {
      e.printStackTrace();
    }
  }

  private void rollBack_login() {
    try {
      rollbackStatement.execute();
      conn.setAutoCommit(true);
      logInUserStatement.clearParameters();
    } catch (SQLException e) {
      e.printStackTrace();
    }
  }

  private void commitTransaction() {
    try {
      commitStatement.execute();
      conn.setAutoCommit(true);
    } catch (SQLException e) {
      e.printStackTrace();
    }
  }

  private void rollBackTransaction() {
    try {
      rollbackStatement.execute();
      conn.setAutoCommit(true);
    } catch (SQLException e) {
      e.printStackTrace();
    }
  }

  /**
   * Takes a user's username and password and attempts to log the user in.
   *
   * @param username user's username
   * @param password user's password
   *
   * @return If someone has already logged in, then return "User already logged in\n" For all other
   *         errors, return "Login failed\n". Otherwise, return "Logged in as [username]\n".
   */
  public String transaction_login(String username, String password) {
    // toLowerCase
    // userName存不存在
    // password对不对
    // check User 是否log in (boolean)
    username = username.toLowerCase();
    try {
      // begin Transaction
      conn.setAutoCommit(false);
      beginTranStatement.executeUpdate();
      if(loginUser == null) {
        logInUserStatement.setString(1, username);
        ResultSet rsPassword = logInUserStatement.executeQuery();
        while (rsPassword.next()) {
          byte[] salt = rsPassword.getBytes("salt");
          byte[] origPW = rsPassword.getBytes("password");
          byte[] hashedPW = hash(password, salt);
          rsPassword.close();               // 注意！！！！！！！！！！！！！！！！！！！！！这个close()的位置可能不太对！！！！！！！
          if (Arrays.equals(origPW, hashedPW)) {
            loginUser = username;
            // valid - commit, set auto True, clearParameters
            commitStatement.execute();
            conn.setAutoCommit(true);
            logInUserStatement.clearParameters();

            return "Logged in as " + username + "\n";
          } else {
            // rollback, set auto True, clearParameters
            rollBack_login();
            return "Login failed\n";
          }
        }
      } else {
        // rollback, set auto True, clearParameters
        rollBack_login();
        return "User already logged in\n";
      }
      // commit, set auto True, clearParameters
      rollBack_login();
      return "Login failed\n";
    } catch (SQLException e) {
      // commit, set auto True, clearParameters
      //e.printStackTrace();
      rollBack_login();
      return "Login failed\n";
    } finally {
      checkDanglingTransaction();
    }
  }

  /**
   * Implement the create user function.
   *
   * @param username   new user's username. User names are unique the system.
   * @param password   new user's password.
   * @param initAmount initial amount to deposit into the user's account, should be >= 0 (failure
   *                   otherwise).
   *
   * @return either "Created user {@code username}\n" or "Failed to create user\n" if failed.
   */
  public String transaction_createCustomer(String username, String password, int initAmount) {
    if (username.length() == 0 || password.length() == 0 || initAmount < 0) {
      return "Failed to create user\n";
    }
    username = username.toLowerCase();
    // 加密 hash the password
    byte[] hash = hash(password, null);
    // 保存 save username, hash, initAmount, salt to the User
    try {
      // begin Transaction
      conn.setAutoCommit(false);
      beginTranStatement.executeUpdate();

      createUserStatement.setString(1, username);
      createUserStatement.setBytes(2, hash);
      createUserStatement.setInt(3, initAmount);
      createUserStatement.executeUpdate();
      // valid - commit, set auto True, clearParameters
      commitStatement.execute();
      conn.setAutoCommit(true);
      createUserStatement.clearParameters();
    } catch (SQLException e) {
      // commit, set auto True, clearParameters
      //e.printStackTrace();
      rollBack_create();
      return "Failed to create user\n";
    } finally {
      checkDanglingTransaction();
    }
    return "Created user "+username+"\n";
  }

  private byte[] hash(String password, byte[] salt) {
    // 如果新用户, 生成salt 并且 store salt into database
    if (salt == null) {
      SecureRandom random = new SecureRandom();
      salt = new byte[16];
      random.nextBytes(salt);
      try {
        createUserStatement.setBytes(4, salt);
      } catch (SQLException e) {
        e.printStackTrace();
      }
    }
    // 生成hash
    KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, HASH_STRENGTH, KEY_LENGTH);
    SecretKeyFactory factory = null;
    byte[] hash = null;
    try {
      factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
      hash = factory.generateSecret(spec).getEncoded();
      return hash;
    } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
      throw new IllegalStateException();
    }
  }

  // 所有直飞路线的集合 - Map<String, Flight>
  private Map<String, Flight> directSearch(String originCity, String destinationCity, int dayOfMonth, int numberOfItineraries) {
    Map<String, Flight> directItineraries = new HashMap<>();
    try {
      // begin Transaction
      conn.setAutoCommit(false);
      beginTranStatement.executeUpdate();

      // directSearchStatement
      directSearchStatement.setInt(1, numberOfItineraries);
      directSearchStatement.setString(2, originCity);
      directSearchStatement.setString(3, destinationCity);
      directSearchStatement.setInt(4, dayOfMonth);
      ResultSet rs = directSearchStatement.executeQuery();
      int cnt = 0; // 记录读取了多少个row
      while(rs.next()) {
        if(cnt >= numberOfItineraries) break;
        // 从ResultSet里面提取路线信息到List<Flight> directItineraries
        int fid = rs.getInt("fid");
        String carrierId = rs.getString("carrier_id");
        int flightNum = rs.getInt("flight_num");
        int time = rs.getInt("actual_time");
        int capacity = rs.getInt("capacity");
        int price = rs.getInt("price");
        Flight flight = new Flight(fid, dayOfMonth, carrierId, flightNum+"", originCity, destinationCity,
                time, capacity, price);
        directItineraries.put(fid+"@", flight);
        cnt++;
      }
      // valid - commit, set auto True, clearParameters
      commitStatement.execute();
      conn.setAutoCommit(true);
      directSearchStatement.clearParameters();
      rs.close();
    } catch (SQLException e) {
      e.printStackTrace();
    } finally {
      checkDanglingTransaction();
    }
    return directItineraries;
  }

  private Map<String, List<Flight>> oneHopSearch(String originCity, String destinationCity, int dayOfMonth, int numberOfItineraries) {
    Map<String, List<Flight>> oneHopItineraries = new HashMap<>();
    try {
      // begin Transaction
      conn.setAutoCommit(false);
      beginTranStatement.executeUpdate();

      oneHopSearchStatement.setInt(1, numberOfItineraries);
      oneHopSearchStatement.setString(2, originCity);
      oneHopSearchStatement.setString(3, destinationCity);
      oneHopSearchStatement.setString(4, destinationCity);
      oneHopSearchStatement.setInt(5, dayOfMonth);
      oneHopSearchStatement.setInt(6, dayOfMonth);
      ResultSet rs = oneHopSearchStatement.executeQuery();
      int cnt = 0; // 记录读取了多少个row
      while(rs.next()) {
        if(cnt >= numberOfItineraries) break;
        int F1_fid = rs.getInt("F1_fid");
        int F1_dom = rs.getInt("F1_dom");
        String F1_cid = rs.getString("F1_cid");
        int F1_fn = rs.getInt("F1_fn");
        String F1_oc = rs.getString("F1_oc");
        String F1_dc = rs.getString("F1_dc");
        int F1_time = rs.getInt("F1_time");
        int F1_cap = rs.getInt("F1_cap");
        int F1_price = rs.getInt("F1_price");
        Flight flight1 = new Flight(F1_fid, F1_dom, F1_cid, F1_fn+"", F1_oc, F1_dc,
                F1_time, F1_cap, F1_price);
        int F2_fid = rs.getInt("F2_fid");
        int F2_dom = rs.getInt("F2_dom");
        String F2_cid = rs.getString("F2_cid");
        int F2_fn = rs.getInt("F2_fn");
        String F2_oc = rs.getString("F2_oc");
        String F2_dc = rs.getString("F2_dc");
        int F2_time = rs.getInt("F2_time");
        int F2_cap = rs.getInt("F2_cap");
        int F2_price = rs.getInt("F2_price");
        Flight flight2 = new Flight(F2_fid, F2_dom, F2_cid, F2_fn+"", F2_oc, F2_dc,
                F2_time, F2_cap, F2_price);
        List<Flight> flights = new ArrayList<>();
        flights.add(flight1);
        flights.add(flight2);
        oneHopItineraries.put(F1_fid+"@"+F2_fid, flights);
        cnt++;
      }
      // valid - commit, set auto True, clearParameters
      commitStatement.execute();
      conn.setAutoCommit(true);
      oneHopSearchStatement.clearParameters();
      rs.close();

    } catch (SQLException e) {
      e.printStackTrace();
    } finally {
      checkDanglingTransaction();
    }
    return oneHopItineraries;
  }

  /**
   * Implement the search function.
   *
   * Searches for flights from the given origin city to the given destination city, on the given day
   * of the month. If {@code directFlight} is true, it only searches for direct flights, otherwise
   * is searches for direct flights and flights with two "hops." Only searches for up to the number
   * of itineraries given by {@code numberOfItineraries}.
   *
   * The results are sorted based on total flight time.
   *
   * @param originCity
   * @param destinationCity
   * @param directFlight        if true, then only search for direct flights, otherwise include
   *                            indirect flights as well
   * @param dayOfMonth
   * @param numberOfItineraries number of itineraries to return
   *
   * @return If no itineraries were found, return "No flights match your selection\n". If an error
   *         occurs, then return "Failed to search\n".
   *
   *         Otherwise, the sorted itineraries printed in the following format:
   *
   *         Itinerary [itinerary number]: [number of flights] flight(s), [total flight time]
   *         minutes\n [first flight in itinerary]\n ... [last flight in itinerary]\n
   *
   *         Each flight should be printed using the same format as in the {@code Flight} class.
   *         Itinerary numbers in each search should always start from 0 and increase by 1.
   *
   * @see Flight#toString()
   */
  public String transaction_search(String originCity, String destinationCity, boolean directFlight,
                                   int dayOfMonth, int numberOfItineraries) {
    // directSearch
    if(directFlight) {
      Map<String, Flight> directItineraries = directSearch(originCity, destinationCity, dayOfMonth, numberOfItineraries);
      // 如果没有飞机 return no flight;
      if(directItineraries.size() == 0) return "No flights match your selection\n";
      return sortDirectItineraries(directItineraries);
    }


    // 先directSearch + 再oneHopSearch
    Map<String, Flight> directItineraries = directSearch(originCity, destinationCity, dayOfMonth, numberOfItineraries);
    // 如果没有飞机
    if(directItineraries.size() == 0) return "No flights match your selection\n";
    // 可以提前结束了 不用进行 oneHopSearch
    if(directItineraries.size() >= numberOfItineraries) {
      // 直接sort and return
      return sortDirectItineraries(directItineraries);
    }
    int rest = numberOfItineraries-directItineraries.size();
    Map<String, List<Flight>> oneHopItineraries = oneHopSearch(originCity, destinationCity, dayOfMonth, rest);
    // sort
    return sortAllItineraries(directItineraries, oneHopItineraries);
  }

  private String sortDirectItineraries(Map<String, Flight> directItineraries) {
    // sort directItineraries, 按时间排的， 如果时间一样，则按照fid的大小排
    List<Flight> list = new ArrayList<>();
    list.addAll(directItineraries.values());
    Collections.sort(list, (a, b)-> {
      if (a.time == b.time) return a.fid-b.fid;
      else return a.time-b.time;
    });
    // 把结果在用StringBuilder链接 —> return
    StringBuffer sb = new StringBuffer();
    for(int i = 0; i < list.size(); i++) {
      Flight flight = list.get(i);
      // searchReturnedFlights key -- itineraryId, val : List<Flight>
      List<Flight> returnedFlights = new ArrayList<>();
      returnedFlights.add(flight);
      searchReturnedFlights.put(i, returnedFlights);
      // key -- itineraryId, val: day_of_month
      sb.append("Itinerary "+i+": 1 flight(s), "+flight.time+" minutes\n"+flight.toString()+"\n");
    }
    return sb.toString();
  }

  private String sortAllItineraries(Map<String, Flight> directItineraries, Map<String, List<Flight>> oneHopItineraries) {
    // 把 directItineraries, indirectItineraries 的key加到list里面去
    // [time, 第一个Id, 第二个ID (-1 if not exists)]
    List<int[]> list = new ArrayList<>();
    for(String s : directItineraries.keySet()) {
      Flight flight = directItineraries.get(s);
      list.add(new int[]{flight.time, flight.fid, -1});
    }
    for(String s : oneHopItineraries.keySet()) {
      List<Flight> flights = oneHopItineraries.get(s);
      Flight flight1 = flights.get(0);
      Flight flight2 = flights.get(1);
      list.add(new int[]{flight1.time+flight2.time, flight1.fid, flight2.fid});
    }
    Collections.sort(list, (a, b)-> {
      if(a[0] != b[0]) return a[0]-b[0];
      else if(a[1] != b[1]) return a[1]-b[1];
      else return a[2]-b[2];
    });

    StringBuffer sb = new StringBuffer();
    for(int i = 0; i < list.size(); i++) {
      int[] l = list.get(i);
      if(l[2] == -1) {
        // 说明是单程
        Flight flight = directItineraries.get(l[1]+"@");
        // searchReturnedFlights key -- itineraryId, val : List<Flight>
        List<Flight> returnedFlights = new ArrayList<>();
        returnedFlights.add(flight);
        searchReturnedFlights.put(i, returnedFlights);
        sb.append("Itinerary "+i+": 1 flight(s), "+flight.time+" minutes\n"+flight.toString()+"\n");
      }
      else {
        // 说明是双
        List<Flight> flights = oneHopItineraries.get(l[1]+"@"+l[2]);
        Flight flight1 = flights.get(0);
        Flight flight2 = flights.get(1);
        int time = flight1.time + flight2.time;
        List<Flight> returnedFlights = new ArrayList<>();
        returnedFlights.add(flight1);
        returnedFlights.add(flight2);
        searchReturnedFlights.put(i, returnedFlights);
        sb.append("Itinerary "+i+": 2 flight(s), "+time+" minutes\n"+flight1.toString()+"\n"+flight2.toString()+"\n");
      }
    }
    return sb.toString();
  }


  /**
   * Implements the book itinerary function.
   *
   * @param itineraryId ID of the itinerary to book. This must be one that is returned by search in
   *                    the current session.
   *
   * @return If the user is not logged in, then return "Cannot book reservations, not logged in\n".
   *         If the user is trying to book an itinerary with an invalid ID or without having done a
   *         search, then return "No such itinerary {@code itineraryId}\n". If the user already has
   *         a reservation on the same day as the one that they are trying to book now, then return
   *         "You cannot book two flights in the same day\n". For all other errors, return "Booking
   *         failed\n".
   *
   *         And if booking succeeded, return "Booked flight(s), reservation ID: [reservationId]\n"
   *         where reservationId is a unique number in the reservation system that starts from 1 and
   *         increments by 1 each time a successful reservation is made by any user in the system.
   */
  public String transaction_book(int itineraryId) {
    // CC1: check User是否Login
    if(loginUser == null) {
      return "Cannot book reservations, not logged in\n";
    }
    // CC2: check itineraryId 是否valid
    if(!searchReturnedFlights.containsKey(itineraryId)) {
      return "No such itinerary " + itineraryId+ "\n";
    }
    try {
      conn.setAutoCommit(false);
      beginTranStatement.executeUpdate();

      // CC3: check reservation table, 如果一个用户 同一天 trying to 订同一个路线 - "You cannot book two flights in the same day\n" // check day_of_month 其实可以隐藏在check two Flights里面 - 因为只要(f1_id, f2_id)一样, day_of_month一定一样
      Reservation reservation = validateDuplicateRes(itineraryId);
      if(reservation == null) {
        rollBackTransaction();
        return "You cannot book two flights in the same day\n";
      }

      // CC4: check flight capacity -- 从Flight里面的数据 - 从Reservation里面拿数据
      List<Flight> flights = searchReturnedFlights.get(itineraryId);
      for(Flight flight : flights) {
        if(!validateCapacity(flight, itineraryId)) {
          rollBackTransaction();
          //System.out.println("validate capacity failed ------------------------------------------------------------------------------------------------");
          return "Booking failed\n";
        }
      }

      // valid - successfully book - update Reservation check size, assign new res_id (unique - starting from 1 and increase by 1)
      int res_id = generateResId();
      createReservation(res_id, reservation);
      commitTransaction();
      return "Booked flight(s), reservation ID: "+res_id+"\n";
    } catch (SQLException e) {
      if (isDeadLock(e)) {
        return transaction_book(itineraryId);
      } else {
        //e.printStackTrace();
        // System.out.println("all other error ------------------------------------------------------------------------------------------------");
        rollBackTransaction();
        return "Booking failed\n";
      }
    } finally {
      checkDanglingTransaction();
    }
  }

  private int generateResId() throws SQLException {
    int res_id = 0;
    ResultSet rsSize = null;
    rsSize = checkReservationSizeStatement.executeQuery();
    while (rsSize.next()) {
      int size = rsSize.getInt("cnt");
      res_id = size+1;
    }
    rsSize.close();
    return res_id;
  }

  private void createReservation(int res_id, Reservation reservation) throws SQLException {
    createReservationStatement.clearParameters();
    createReservationStatement.setInt(1, res_id);
    createReservationStatement.setString(2, loginUser);
    createReservationStatement.setInt(3, reservation.dayOfMonth);
    createReservationStatement.setInt(4, reservation.f1Id);
    if(reservation.f2Id == -1) createReservationStatement.setNull(5, java.sql.Types.INTEGER);
    else createReservationStatement.setInt(5, reservation.f2Id);
    createReservationStatement.setInt(6, reservation.price);
    createReservationStatement.setInt(7, reservation.paid);
    createReservationStatement.setInt(8, reservation.canceled);
    createReservationStatement.executeUpdate();
  }

  // 拿一个 itineraryId, 检查是否 duplicate 返回 reservation数据
  private Reservation validateDuplicateRes(int itineraryId) throws SQLException {
    List<Flight> flights = searchReturnedFlights.get(itineraryId);
    int dayOfMonth = -1, f1Id = -1, f2Id = -1, price = 0, paid = 0, canceled = 0;
    if(flights.size() == 2) {
      dayOfMonth = flights.get(0).dayOfMonth;
      f1Id = flights.get(0).fid;
      f2Id = flights.get(1).fid;
      price = flights.get(0).price + flights.get(1).price;
    }
    else {
      dayOfMonth = flights.get(0).dayOfMonth;
      f1Id = flights.get(0).fid;
      price = flights.get(0).price;
    }
    getUserResOfTheDayStatement.clearParameters();
    getUserResOfTheDayStatement.setString(1, loginUser);
    getUserResOfTheDayStatement.setInt(2, dayOfMonth);
    ResultSet rs = getUserResOfTheDayStatement.executeQuery();
    rs.next();
    int cnt = rs.getInt("cnt");
    if(cnt > 0) return null;
    rs.close();
    return new Reservation(dayOfMonth, f1Id, f2Id, price, paid, canceled);
  }

  private boolean validateCapacity(Flight flight, int itineraryId) throws SQLException {
    checkDefaultCapStatement.clearParameters();
    checkDefaultCapStatement.setInt(1, flight.fid);
    ResultSet rsCap = checkDefaultCapStatement.executeQuery();

    int cap = 0;
    rsCap.next();
    cap = rsCap.getInt("capacity");
    rsCap.close();

    int haveReserved = 0;
    checkReserveCapStatement.clearParameters();
    checkReserveCapStatement.setInt(1, flight.fid);
    checkReserveCapStatement.setInt(2, flight.fid);
    ResultSet rsRes = checkReserveCapStatement.executeQuery();

    rsRes.next();
    haveReserved = rsRes.getInt("cnt");
    if (haveReserved >= cap) {
      rsRes.close();
      return false;
    }
    rsRes.close();
    return true;
  }


  /**
   * Implements the pay function.
   *
   * @param reservationId the reservation to pay for.
   *
   * @return If no user has logged in, then return "Cannot pay, not logged in\n" If the reservation
   *         is not found / not under the logged in user's name, then return "Cannot find unpaid
   *         reservation [reservationId] under user: [username]\n" If the user does not have enough
   *         money in their account, then return "User has only [balance] in account but itinerary
   *         costs [cost]\n" For all other errors, return "Failed to pay for reservation
   *         [reservationId]\n"
   *
   *         If successful, return "Paid reservation: [reservationId] remaining balance:
   *         [balance]\n" where [balance] is the remaining balance in the user's account.
   */
  public String transaction_pay(int reservationId) {
    // check user是否login
    if(loginUser == null) {
      return "Cannot pay, not logged in\n";
    }
    try {
      conn.setAutoCommit(false);
      beginTranStatement.executeUpdate();

      getUserInfoStatement.clearParameters();
      getUserInfoStatement.setInt(1, reservationId);
      getUserInfoStatement.setString(2, loginUser);
      ResultSet rsUser = getUserInfoStatement.executeQuery();
      // 如果没有username: Cannot find unpaid reservation
      if (!rsUser.next()) {
        rsUser.close();
        rollBackTransaction();
        return "Cannot find unpaid reservation " + reservationId + " under user: " + loginUser + "\n";
      }
      // user已经付过钱了
      int paid = rsUser.getInt("paid");  // 0 unpaid, 1 paid
      if(paid == 1) {
        rsUser.close();
        rollBackTransaction();
        return "Cannot find unpaid reservation " + reservationId + " under user: " + loginUser + "\n";
      }

      int ticketPrice = rsUser.getInt("price");
      int userBalance = rsUser.getInt("initAmount");
      rsUser.close();
      if (ticketPrice > userBalance) {
        rollBackTransaction();
        return "User has only " + userBalance + " in account but itinerary costs " + ticketPrice + "\n";
      }

      refundStatement.clearParameters();
      int balance = userBalance - ticketPrice;
      refundStatement.setInt(1, balance);
      refundStatement.setString(2, loginUser);
      refundStatement.executeUpdate();
      updateReservStatement.clearParameters();
      updateReservStatement.setInt(1, 1);
      updateReservStatement.setInt(2, reservationId);
      updateReservStatement.executeUpdate();
      commitTransaction();
      return "Paid reservation: " + reservationId + " remaining balance: " + balance + "\n";
    } catch (SQLException e) {
      //e.printStackTrace();
      rollBackTransaction();
      return "Failed to pay for reservation " + reservationId + "\n";
    } finally {
      checkDanglingTransaction();
    }
  }

  /**
   * Implements the reservations function.
   *
   * @return If no user has logged in, then return "Cannot view reservations, not logged in\n" If
   *         the user has no reservations, then return "No reservations found\n" For all other
   *         errors, return "Failed to retrieve reservations\n"
   *
   *         Otherwise return the reservations in the following format:
   *
   *         Reservation [reservation ID] paid: [true or false]:\n [flight 1 under the
   *         reservation]\n [flight 2 under the reservation]\n Reservation [reservation ID] paid:
   *         [true or false]:\n [flight 1 under the reservation]\n [flight 2 under the
   *         reservation]\n ...
   *
   *         Each flight should be printed using the same format as in the {@code Flight} class.
   *
   * @see Flight#toString()
   */
  public String transaction_reservations() {
    // check user是否login
    if(loginUser == null) {
      return "Cannot view reservations, not logged in\n";
    }
    StringBuilder sb = new StringBuilder();
    try {
      checkReservationStatement.clearParameters();
      checkReservationStatement.setString(1, loginUser);
      ResultSet rs = checkReservationStatement.executeQuery();
      while (rs.next()) {
        int res_id = rs.getInt("res_id");
        Integer f1_id = (Integer) rs.getObject("f1_id");
        Integer f2_id = (Integer) rs.getObject("f2_id");
        int paid = rs.getInt("paid");
        String paidStatus = paid == 0 ? "false" : "true";
        Flight f1 = getFlightHelper(f1_id);
        Flight f2 = getFlightHelper(f2_id);
        if(f2 == null) {
          sb.append("Reservation " + res_id + " paid: "+ paidStatus + ":\n" + f1.toString() + "\n");
        }
        else {
          sb.append("Reservation " + res_id + " paid: "+ paidStatus + ":\n" + f1.toString() + "\n" + f2.toString() + "\n");
        }
      }
      rs.close();
      if(sb.toString().length() == 0) {
        return "No reservations found\n";
      }
      return sb.toString();
    } catch (SQLException e) {
      //e.printStackTrace();
      return "Failed to retrieve reservations\n";
    } finally {
      checkDanglingTransaction();
    }
  }

  private Flight getFlightHelper(Integer fid) {
    if(fid == null) return null;
    Flight flight = null;
    try {
      getFlightStatement.clearParameters();
      getFlightStatement.setInt(1, fid);
      ResultSet rs = getFlightStatement.executeQuery();
      while(rs.next()) {
        int dayOfMonth = rs.getInt("day_of_month");
        String carrierId = rs.getString("carrier_id");
        int flightNum = rs.getInt("flight_num");
        String originCity = rs.getString("origin_city");
        String destinationCity = rs.getString("dest_city");
        int time = rs.getInt("actual_time");
        int capacity = rs.getInt("capacity");
        int price = rs.getInt("price");
        flight = new Flight(fid, dayOfMonth, carrierId, flightNum+"", originCity, destinationCity, time, capacity, price);
      }
      rs.close();
    } catch (SQLException e) {
      e.printStackTrace();
    } finally {
      checkDanglingTransaction();
    }
    return flight;
  }

  public void updateCancel(int reservationId) throws SQLException {
    cancelReservationStatement.clearParameters();
    cancelReservationStatement.setInt(1, reservationId);
    cancelReservationStatement.executeUpdate();
  }

  public void updatePaid() throws SQLException {
    makeUnpaidStatement.clearParameters();
    makeUnpaidStatement.setString(1, loginUser);
    makeUnpaidStatement.executeUpdate();
  }

  /**
   * Implements the cancel operation.
   *
   * @param reservationId the reservation ID to cancel
   *
   * @return If no user has logged in, then return "Cannot cancel reservations, not logged in\n" For
   *         all other errors, return "Failed to cancel reservation [reservationId]\n"
   *
   *         If successful, return "Canceled reservation [reservationId]\n"
   *
   *         Even though a reservation has been canceled, its ID should not be reused by the system.
   */
  public String transaction_cancel(int reservationId) {
    if(loginUser == null) {
      return "Cannot cancel reservations, not logged in\n";
    }
    try {
      conn.setAutoCommit(false);
      beginTranStatement.executeUpdate();

      // check reservationId是否存在
      getUserInfoStatement.clearParameters();
      getUserInfoStatement.setInt(1, reservationId);
      getUserInfoStatement.setString(2, loginUser);
      ResultSet rsUser = getUserInfoStatement.executeQuery();
      // 如果没有 reservationId: Cannot find unpaid reservation
      if (!rsUser.next()) {
        rsUser.close();
        rollBackTransaction();
        return "Failed to cancel reservation " + reservationId + "\n";
      }

      int paid = rsUser.getInt("paid");
      int refundPrice = rsUser.getInt("price");
      int balance = rsUser.getInt("initAmount");
      rsUser.close();
      // 把canceled 改成 1
      updateCancel(reservationId);
      // if unpaid
      if(paid == 0) {
        commitTransaction();
        return "Canceled reservation " + reservationId + "\n";
      }

      // if paid reservation (reservation里paid是1)-- 把paid变成unpaid, refund
      updatePaid();
      // refund process
      refund(balance+refundPrice);
      commitTransaction();
      return "Canceled reservation " + reservationId + "\n";
    }
    catch (SQLException e) {
      e.printStackTrace();
      rollBackTransaction();
      return "Failed to cancel reservation " + reservationId + "\n";
    } finally {
      checkDanglingTransaction();
    }
  }

  private void refund(int newBalance) throws SQLException {
    refundStatement.clearParameters();
    refundStatement.setInt(1, newBalance);
    refundStatement.setString(2, loginUser);
    refundStatement.executeUpdate();
  }

  /**
   * Example utility function that uses prepared statements
   */
  private int checkFlightCapacity(int fid) throws SQLException {
    checkFlightCapacityStatement.clearParameters();
    checkFlightCapacityStatement.setInt(1, fid);
    ResultSet results = checkFlightCapacityStatement.executeQuery();
    results.next();
    int capacity = results.getInt("capacity");
    results.close();

    return capacity;
  }


  /**
   * Throw IllegalStateException if transaction not completely complete, rollback.
   *
   */
  private void checkDanglingTransaction() {
    try {
      try (ResultSet rs = tranCountStatement.executeQuery()) {
        rs.next();
        int count = rs.getInt("tran_count");
        if (count > 0) {
          throw new IllegalStateException(
                  "Transaction not fully commit/rollback. Number of transaction in process: " + count);
        }
      } finally {
        conn.setAutoCommit(true);
      }
    } catch (SQLException e) {
      throw new IllegalStateException("Database error", e);
    }
  }

  private static boolean isDeadLock(SQLException ex) {
    return ex.getErrorCode() == 1205;
  }

  /**
   * A class to store flight information.
   */
  class Flight {
    public int fid;
    public int dayOfMonth;
    public String carrierId;
    public String flightNum;
    public String originCity;
    public String destCity;
    public int time;
    public int capacity;
    public int price;

    public Flight(int fid, int dayOfMonth, String carrierId, String flightNum, String originCity, String destCity,
                  int time, int capacity, int price) {
      this.fid = fid;
      this.dayOfMonth = dayOfMonth;
      this.carrierId = carrierId;
      this.flightNum = flightNum;
      this.originCity = originCity;
      this.destCity = destCity;
      this.time = time;
      this.capacity = capacity;
      this.price = price;
    }

    @Override
    public String toString() {
      return "ID: " + fid + " Day: " + dayOfMonth + " Carrier: " + carrierId + " Number: "
              + flightNum + " Origin: " + originCity + " Dest: " + destCity + " Duration: " + time
              + " Capacity: " + capacity + " Price: " + price;
    }
  }

  class Reservation {
    public int dayOfMonth;
    public int f1Id;
    public int f2Id;
    public int price;
    public int paid;
    public int canceled;


    public Reservation(int dayOfMonth, int f1Id, int f2Id, int price, int paid, int canceled) {
      this.dayOfMonth = dayOfMonth;
      this.f1Id = f1Id;
      this.f2Id = f2Id;
      this.price = price;
      this.paid = paid;
      this.canceled = canceled;
    }
  }
}