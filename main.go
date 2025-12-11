package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"google.golang.org/api/drive/v3"
	"google.golang.org/api/option"
)

func InitDriveService() {
	ctx := context.Background()

	// 1. Read the JSON string from the environment variable (Set on Render)
	credentialsJSON := os.Getenv("GOOGLE_CREDENTIALS")

	if credentialsJSON == "" {
		// If the variable is missing, log a sever error and halt
		log.Fatalf("Fatal: GOOGLE_CREDENTIALS environment variable not set. Cannot initialize Google Drive client.")
	}

	// 2. Use the credentials string (as a byte slice) to create the client
	// This uses option.WithCredentialsJSON instead of option.WithCredentialsFile

	srv, err := drive.NewService(ctx, option.WithCredentialsJSON([]byte(credentialsJSON)))

	if err != nil {
		log.Fatalf("Unable to retrieve Drive client: %v", err)
	}

	DriveService = srv
	log.Println("Google Drive Service Initalized")
}

func main() {

	InitDriveService()
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
