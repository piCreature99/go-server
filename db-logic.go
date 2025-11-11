package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// Declared as an exported (capitalized) global variable.
var MongoClient *mongo.Client

var MoviesCollection *mongo.Collection
var UsersCollection *mongo.Collection

func ConnectDB() error {
	uri := os.Getenv("MONGODB_URI")
	docs := "www.mongodb.com/docs/drivers/go/current/"
	if uri == "" {
		log.Fatal("Set your 'MONGODB_URI' environment variable. " +
			"See: " + docs +
			"usage-examples/#environment-variable")
	}
	// Use context.Background() for the initial connection attempt
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	var err error
	// establish connection
	MongoClient, err = mongo.Connect(options.Client().
		ApplyURI(uri))
	if err != nil {
		// panic(err)
		return fmt.Errorf("failed to connect to MongoDB: %w", err) // Used in fmt.Errorf to attach a new error to an underlying (wrapped) error,
		// preserving the original error in the chain.
	}
	// Ping to verify connection
	if err := MongoClient.Ping(ctx, nil); err != nil {
		return fmt.Errorf("failed to ping MongoDB: %w", err)
	}
	// disconnect at the end of the function
	// defer func() {
	// if err := MongoClient.Disconnect(context.TODO()); err != nil {
	// 	panic(err)
	// }
	// }()
	// coll := client.Database("sample_mflix").Collection("movies")            // access database
	MoviesCollection = MongoClient.Database("sample_mflix").Collection("test01") // access database
	UsersCollection = MongoClient.Database("authdb").Collection("users")
	log.Println("Successfully connected to MongoDB and initialized collections.")

	return nil
	// 1. Define the document to insert using bson.M (unordered map)
	// newMovie := bson.M{ // map initialization
	// 	"title":  "Go Driver Insert Example",
	// 	"year":   2025,
	// 	"plot":   "A movie about learning how to use the Go MongoDB Driver.",
	// 	"genres": []string{"coding", "tutorial", "comedy"},
	// }

	// // 2. Perform the InsertOne operation
	// // ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	// // defer cancel() // Important: If we use context.Background(), we must cancel it.
	// // ensures that the context's resources are cleaned up as soon as the surrounding function finishes,
	// // regardless of whether the timeout was reached or the database operation completed successfully.
	// // Failing to call cancel() can lead to memory leaks.
	// insertResult, err := MoviesCollection.InsertOne(ctx, newMovie)
	// if err != nil {
	// 	log.Fatal("Failed to insert document: ", err)
	// }

	// // 3. Print the ID of the newly inserted document
	// fmt.Printf("Successfully inserted a document with ID: %v\n", insertResult.InsertedID)

	// title := "Back to the Future"
	// var result bson.M                                             // of type map[string]interface, string is of keys, interface is of values
	// err = coll.FindOne(context.TODO(), bson.D{{"title", title}}). // You are using context.TODO() because the driver demands a context,
	// 	// and you haven't yet refactored the code to use the actual context of a web request (like r.Context() from your HTTP handler).
	// 	// It serves as a non-nil placeholder to satisfy the function signature.
	// 	// bson.D is a slice, accessing using [index]
	// 	Decode(&result) // decodes the BSON data and marshals it into the Go variable result
	// if err == mongo.ErrNoDocuments {
	// 	fmt.Printf("No document was found with the title %s\n", title)
	// 	return
	// }
	// if err != nil {
	// 	panic(err)
	// }
	// jsonData, err := json.MarshalIndent(result, "", "    ")
	// if err != nil {
	// 	panic(err)
	// }
	// fmt.Printf("%s\n", jsonData)
}

// To integrate your DB logic with your HTTP handlers, you must refactor ConnectDB() to:
// Return an error to signal connection failure.
// Assign the connected client and collection to the global variables.
// Remove the immediate disconnection logic, as the connection must stay open for the server.

// NOTE: All the Insert and Find logic was removed from ConnectDB()
// because those operations should be in separate functions or HTTP handlers.
