#! /bin/bash

rm MacOS/server

go build && mv server.go MacOS/server
