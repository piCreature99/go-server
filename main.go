package main

import (
	"context"
	"fmt"
	"log"
	"time"
)

func main() {

	// 1. CONNECT TO DATABASE FIRST
	// ConnectDB initializes the global MongoClient and MoviesCollection
	fmt.Printf("Starting application...\n")
	if err := ConnectDB(); err != nil { // if initializer (initalize err then check it right after)
		log.Fatalf("FATAL: Database connection failed: %v", err) // %v is sufficient because you are simply displaying the final,
		// full error message to the user.
	}

	// 2. SCHEDULE DISCONNECT (Cleanup)
	// This uses the global MongoClient (defined in db-logic.go)
	defer func() {
		log.Println("Gracefully disconnecting MongoDB client...")
		disconnectCtx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		// This line assumes MongoClient is a global variable from db-logic.go
		// and is the *mongo.Client type.
		// We use the Disconnect function defined by the mongo driver
		if err := MongoClient.Disconnect(disconnectCtx); err != nil {
			log.Printf("Error during MongoDB disconnection: %v", err)
		}
	}()

	// 3. START HTTP SERVER
	// The Server() function will now be able to use the connected MoviesCollection.
	fmt.Printf("HTTP server starting...\n")
	Server()

	// Any code below Server() will only run after the server shuts down (unless Server() runs in a goroutine).

}
