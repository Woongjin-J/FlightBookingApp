--Users: A user has a username (varchar), password (varbinary), and balance (int) in their account.
--All usernames should be unique in the system. Each user can have any number of reservations.
--Usernames are case insensitive (this is the default for SQL Server).
--Since we are salting and hashing our passwords through the Java application, passwords are case sensitive.
--You can assume that all usernames and passwords have at most 20 characters.

--Itinerary: An itinerary is either a direct flight (consisting of one flight: origin --> destination) or
--a one-hop flight (consisting of two flights: origin --> stopover city, stopover city --> destination). Itineraries are returned by the search command.

--Reservations: A booking for an itinerary, which may consist of one (direct) or two (one-hop) flights.
--Each reservation can either be paid or unpaid, cancelled or not, and has a unique ID.


CREATE TABLE Users (
    username varchar(20) PRIMARY KEY,
    password varbinary(20) SQL_Latin1_General_CP1_CS_AS,
    balance int
)

create table Reservations (
    res_id int,
    username varchar(20) references Users,
    origin_city varchar(20),
    dest_city varchar(20),
    duration int,
    dpt_day int?,
    flight1id int，
    flight2id int,
    capacity int,
    price int,
    paid int,
    canceled int
);