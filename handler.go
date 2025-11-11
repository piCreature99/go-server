package main

import (
	// Note: Also remove the 'os' import.

	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"

	"github.com/golang-jwt/jwt/v5"
	// "os"
)

const keyServerAddr = "serverAddr"

// const jwtSecret = "Your_super_secret_and_log_key_here" // remember to use the secret from your env file later
var jwtSecret string

// -This is a map

// CREATE A STSRUCT FOR MONGODB USER AUTHENTICATION
// BSON tags map the Go struct fields to the document fields in MongoDB.
// Assuming your user documents have 'username' and 'password' fields.
type UserAuth struct {
	// Your UserAuth struct needs both tags(json:"username bson:"username") to handle the data coming in (JSON from the client)
	// and the data going out (BSON for MongoDB).
	// Look for a key named username in the incoming JSON, and map its value to the Go field named Username
	// The reason the UserAuth struct fields still include the json:"..." tag is purely for practicality,
	// flexibility, and code clarity.
	// For example, you might create a separate handler later to return public user data:
	Username string `json:"username bson:"username"`
	Password string `json:"password" bson:"password"`
	// You can add a Role field here for later use
	Role string `json:"role" bson:"role"`
}

// DELETE THIS HARDCODED MAP
var users = map[string]string{
	"testuser": "password123",
}

// -This is a struct
// Define the struct type first (declaration)
type User struct {
	ID       int
	Username string
	Email    string
	IsActive bool
}

// CORRECT: Variable declaration using 'var' at the package level
var admin = User{
	ID:       1,
	Username: "admin_user",
	Email:    "admin@example.com",
	IsActive: true,
}

// -this is a slice
// Create an array
// var myArray = [6]string{"A", "B", "C", "D", "E", "F"}

// // Create a slice that references elements from index 1 (inclusive) to 4 (exclusive)
// var s1 = myArray[1:4] // References "B", "C", "D"
// // s has len=3, cap=3
// var s = []int{1, 2, 3}

// s is full, append triggers a new, larger underlying array
// s = append(s, 4)
// fmt.Println(s1)     // Output: [B C D]
// fmt.Println(len(s1)) // Output: 3
// fmt.Println(cap(s1)) // Output: 5 (from 'B' to the end of myArray)

// LOGIN HANDLER
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 1. Decode credentials from request body

	var creds struct { // similar structural purpose to interface, we're not using bson.m in this case because it's more type safe with clarity
		Username string `json:"username"`
		Password string `json:"password"`
	}
	// it's still fine if the body have extra fields

	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil { // get the body from curl and decode it into go variable with structure of creds
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// 2.Simulate User Authentication
	// expectedPassword, ok := users[creds.Username] // find the key name and assign value of that key to the expectedPassword,
	// 2. Query MongoDB for the user (REPLACING THE MAP LOOKUP)
	var foundUser UserAuth // Struct to hold the retrieved document

	// Use the global collection variable (MoviesCollection, assuming it holds user data for now)
	coll := UsersCollection
	// insert data to db first: curl -X POST -H "Content-Type: application/json" -d "{\"username\": \"testuser\", \"password\": \"password123\", \"role\": \"member\"}" http://localhost:3333/insert
	if coll == nil {
		log.Println("MongoDB collection not initialized.")
		http.Error(w, "Server configuration error", http.StatusInternalServerError)
		return
	}

	// Filter to find the document by username
	filter := bson.M{"username": creds.Username}

	// Create a request context with a timeout
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()

	// Execute the query
	err := coll.FindOne(ctx, filter).Decode(&foundUser)

	if err == mongo.ErrNoDocuments {
		// User not found
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	} else if err != nil {
		// Database or connection error
		log.Printf("MongoDB Find One error : %v", err)
		http.Error(w, "Internal authentication error", http.StatusInternalServerError)
		return
	}

	// 3. Validate Password (NOTE: USE HASHED PASSWORDS IN PRODUCTION!)
	if foundUser.Password != creds.Password {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// 4. Create the JWT Token (Now includes the role from MongoDB)
	expirationTime := time.Now().Add(5 * time.Minute)

	claims := jwt.MapClaims{
		"user": foundUser.Username,
		"role": foundUser.Role, // <-- INCLUDE THE ROLE FROM THE DB
		"exp":  expirationTime.Unix(),
	}

	// return ok as false if key was not found
	// if !ok || expectedPassword != creds.Password {
	// 	http.Error(w, "Invalid credentials", http.StatusUnauthorized)
	// 	return
	// }

	// 3. Create the JWT Token
	// Set token claims (data inside the token)
	// expirationTime := time.Now().Add(5 * time.Minute)
	// type MapClaims map[string]interface{}
	// Because it uses the interface{} type for its values, you can store any type of data—string,
	// number, boolean, or even another map—as a claim in the JWT payload.

	// claims := jwt.MapClaims{ // assign exp time to a user
	// 	"user": creds.Username,
	// 	"exp":  expirationTime.Unix(), // converts the Go-specific time structure (time.Time)
	// 	// into a format required by the JWT standard: a numerical timestamp (seconds since the Unix epoch)
	// }

	// Create the token instance
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	// creating a new, unsigned JSON Web Token (JWT) object.
	// SigningMethodHS256 is a constant representing the HMAC using SHA-256 algorithm.
	// It tells the recipient (the server) how the token was signed, so they know which method to use for verification.
	// HS256 requires a shared secret key

	// Sign the token using the secret key
	tokenString, err := token.SignedString([]byte(jwtSecret))
	// []bypte() converts the secret key from a string into a slice of bytes ([]byte)
	// Go takes the sequence of characters and converts them into their raw binary representation (typically using UTF-8 encoding).
	// The key itself doesn't "look" different to you, but to the computer,
	// it is no longer treated as text. It becomes a sequence of raw bytes
	// (e.g., [89 111 117 114 95 115 117 112 101 114 95 115 101 99 114 101 116 95 97 110 100 95 108 111 103 95 107 101 121 95 104 101 114 101]).
	// SignedString: The final token is a single string with three distinct parts separated by periods
	// Header(Base64).Payload(Base64).Signature(Base64)
	// It looks something like this (the actual content is encoded and varies):
	// eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoidGVzdHVzZXIiLCJleHAiOjE2MzgyNzk2ODZ9.SjY_N1k3V2g1R3g3Z0Y4Z0J0TjRzM0U5cUcwZzJaY21R
	// ** The token has 3 parts separated by a period: the Header, the Payload, and the Signature, the signature is partly from your jwtSecret\
	// the signature (part 3) is created this way: Signature = BLENDER[or HMAC-SHA256](jwtSecret, Header + "." + Payload with Exp Time)
	// the Payload (part 2) is the encoded  version of the following JSON object:
	// {
	// 	"user": "testuser",
	// 	"exp": 1638279686
	// }
	// the Header (part 1)
	// The Header provides instructions to the receiver (your AuthMiddleware) on how to process and verify the token.
	// encoded version of the following JSON object:
	// {
	// 	"alg": "HS256",
	// 	"typ": "JWT"
	// }
	// alg used to specifies the cryptographic algorithm used to sign the token. In your case, "HS256" stands for HMAC using SHA-256
	// When your middleware validates the token, it looks at this claim to know which algorithm
	// it must use with the shared secret (jwtSecret) to calculate and verify the signature (Part 3).
	// type used to specifies the type of the media object, which is usually set to "JWT" to identify the token structure.
	// part 1 is typically static (it stays the same) for all tokens issued by your server, as long as you don't
	// change your security configuration.
	// ** both part 1 and 2 are used in generating the signature (part 3)
	if err != nil {
		log.Printf("Error signing token: %v", err)
		http.Error(w, "Could not generate token", http.StatusInternalServerError)
		return
	}

	// 4. Send the token back to the client
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"token": tokenString}) // print the token to your second terminal
}

// get the token: curl -X POST -H "Content-Type: application/json" -d "{\"username\": \"testuser\", \"password\": \"password123\"}" http://localhost:3333/login
// END LOGIN HANDLER

// AUTHENTICATION MIDDLEWARE/WRAPPER

func AuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// 1. Get the token from the Authorization header
		// header example: curl -X GET http://localhost:8080/profile \
		// -H "Authorization: Bearer <token_string>"
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Missing token", http.StatusUnauthorized)
			return
		}

		// Header format is typically "Bearer TOKEN_STRING"
		// contains the entire string that follows the Authorization: label
		tokenString := ""
		if len(authHeader) > 7 && authHeader[:7] == "Bearer " {
			tokenString = authHeader[7:]
		} else {
			http.Error(w, "Invalid token format", http.StatusUnauthorized)
			return
		}

		// 2. Parse and Validate the token
		// Every interaction with a protected resource, including fetching or updating the user's profile,
		// requires the client to send the JWT, and requires the server to validate it.
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) { // check the jwtSecret and exp time, no need to remembe the token key itself
			// Check the signing method
			// Data stored in *jwt.Token: The token's Claims contain the user's identity (e.g., "user", "role"),
			// but not the secret password.
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(jwtSecret), nil // returns the the server shared secret key (jwtSecret)
		})

		if err != nil || !token.Valid {
			log.Printf("Token validation failed: %v", err)
			http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
			return
		}

		// 3. If token is valid, execute the original handler (the 'next' function)
		next(w, r)
	}
}

func ProfileHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	io.WriteString(w, `{"message": "Welcome to your protected profile!}`)
}

// END AUTHENTICATION MIDDLEWARE/WRAPPER
//TESTING OUT:

// CMD/PowerShell: Escape quotes for JSON body
// curl -X POST -H "Content-Type: application/json" -d "{\"username\": \"testuser\", \"password\": \"password123\"}" http://localhost:3333/login

// verify your token for each protected interaction
// curl -X GET -H "Authorization: Bearer [YOUR_TOKEN]" http://localhost:3333/profile
//END TESTING

func InsertMovieHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed. Only POST is supported.", http.StatusMethodNotAllowed)
		return
	}

	// 2. Use the global collection variable
	// coll := UsersCollection
	coll := MoviesCollection

	// 3. Decode the incoming JSON body into a placeholder map
	var newMovie bson.M

	// Read the request body and decode the JSON directly into the newMovie map
	// The Decode method returns an error if the body is not valid JSON
	if err := json.NewDecoder(r.Body).Decode(&newMovie); err != nil { // transforms the text-based JSON from the client into a Go variable
		log.Printf("[%s] Error decoding request body : %v", r.URL.Path, err)
		http.Error(w, "Invalid JSON body provided", http.StatusBadRequest)
		return
	}

	// 4. Create a context with atimeout tied to the request
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	// 5. Execute the InsertOne query
	insertResult, err := coll.InsertOne(ctx, newMovie) // transforms the Go variable into BSON for the database
	if err != nil {
		log.Printf("[%s] Database insertion error: %v", r.URL.Path, err)
		http.Error(w, "internal server error during insertion", http.StatusInternalServerError)
		return
	}

	// 6. Send the successful JSON response (201 Created)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated) // HTTP 201 Created is
	// the standard status code for successful resource creation

	// Prepare a response object to tell the client the ID of the new document
	response := bson.M{
		"message":    "Movie successfully inserted",
		"insertedID": insertResult.InsertedID,
	}

	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("Error encoding JSON ersponse: %v", err)
		// If encoding fails here, the client likely won't get a proper error either
	}
}

// You will need to use the -X POST flag and the -d flag to provide the JSON body to test the insertion.
// curl -X POST \
//   -H "Content-Type: application/json" \
//   -d '{
//       "title": "A New Go Movie Title",
//       "year": 2023,
//       "director": "Go Developer",
//       "genres": ["test", "comedy"]
//     }' \
//   http://localhost:3333/insert
// curl -X POST -H "Content-Type: application/json" -d "{\"title\": \"A New Go Movie Title\", \"year\": 2023, \"director\": \"Go Developer\", \"genres\": [\"test\", \"comedy\"]}" http://localhost:3333/insert
// Because the JSON standard itself requires double quotes around keys and string values (e.g., "title": "..."),
// these internal quotes must be escaped using a backslash (\) so that the command interpreter knows they are part of
// the data and not meant to terminate the main quoted argument.

// The -H flag allows you to specify a custom HTTP header. For an insertion handler that accepts JSON data,
// you need to set the Content-Type header to tell the server what kind of data is in the request body.

// --- NEW HANDLER FUNCTION ---
func FindMovieHandler(w http.ResponseWriter, r *http.Request) {
	// 1. Get the title from a query parameter (e.g., /movie?title=Back%20to%20the%20Future)
	title := r.URL.Query().Get("title")
	if title == "" {
		http.Error(w, "Missing 'title' query parameter", http.StatusBadRequest)
		return
	}

	// 2. Use the global collection variable from db-logic.go
	// This assumes MoviesCollection was successfully initialized in main.go
	coll := MoviesCollection

	// 3. Create a filter
	filter := bson.M{"title": title}

	var result bson.M // Document will be decoded into this map

	// 4. Create a context with a timeout tied to the request context
	// This ensures the DB operation can't hold up the HTTP request indefinitely.
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	// ctx is used for timeout and dealine, cancellation signal (HTTP Request, if client or user close connection before the query finishes
	// the r.Context() is canceled and the query'll receive that signal and stop), Request-Specific Data (Trace Information):
	// if you assign a unique Request ID or a User's authentication token to the context at the very start of the HTTP handler,
	// every function the handler calls (including FindOne) can access that ID for logging or tracing, as the context is passed along.
	defer cancel()

	// 5. Execute the FindOne query
	err := coll.FindOne(ctx, filter).Decode(&result) // 5 seconds to find

	if err == mongo.ErrNoDocuments {
		w.WriteHeader(http.StatusNotFound)
		io.WriteString(w, fmt.Sprintf("Movie with title '%s' not found.", title))
		// This sequence correctly signals two things to the client:
		// Status Code (404): The requested resource (the movie with the given title) does not exist on the server.
		// Body Content: It then sends a plain text message (io.WriteString) explaining why the 404 occurred.
		return
	}
	if err != nil {
		log.Printf("[%s] Database error: %v", r.URL.Path, err)
		http.Error(w, "Internal server error during query", http.StatusInternalServerError)
		return
	}

	// fmt.Printf("%s: successfully found document for title=%s. Object: \n%+v\n",
	// 	r.Context().Value(keyServerAddr),
	// 	title,
	// 	result,
	// )

	jsonData, err := json.MarshalIndent(result, "", "    ")
	if err != nil {
		panic(err)
	}
	fmt.Printf("%s\n", jsonData)

	// 6. Send the successful JSON response
	w.Header().Set("Content-Type", "application/json")
	// 	Correct Interpretation: When a client receives a response, it first checks the Content-Type header.
	// 	Knowing the type is application/json tells the client:
	// 	How to parse the data: The client knows to use its internal JSON parser.
	// 	How to treat the data: Browsers, for example, will know not to render it as plain text or HTML.

	// Convert the bson.M map into JSON format for the response body
	if err := json.NewEncoder(w).Encode(result); err != nil { // converts the Go map (result) into a JSON string and then writes that string to
		// the http.ResponseWriter (w). (second terminal)
		log.Printf("Error encoding JSON response: %v", err)
		http.Error(w, "Internal server error encoding response", http.StatusInternalServerError)
	}
}

// # Example to test the new handler
// curl 'http://localhost:3333/movie?title=Back%20to%20the%20Future' (ASCII hexadecimal code (for space, this is 20), %20)
// --- END NEW HANDLER FUNCTION ---

// the http.ResponseWriter value (named w in your handlers) is used to **control the response** information
// being written back to the client that made the request, such as the body of the response or the status code.
// http.Request value (named r in your handlers) is used to **get information** about the request that came into the server,
// such as the body being sent in the case of a POST request or information about the client that made the request.
func getRoot(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	hasFirst := r.URL.Query().Has("first")
	first := r.URL.Query().Get("first")
	hasSecond := r.URL.Query().Has("second")
	second := r.URL.Query().Get("second")

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		fmt.Printf("could not read body: %s\n", err)
	}

	// fmt.Printf("got / request\n")
	// fmt.Printf("%s: got / request\n", ctx.Value(keyServerAddr)) // %s here is [::]:3333: for example, returned in your main terminal when receiving requests
	fmt.Printf("%s: got / reuqest. first (%t)=%s, second(%t)=%s, body:\n%s\n",
		ctx.Value(keyServerAddr),
		hasFirst, first,
		hasSecond, second,
		body)
	io.WriteString(w, "This is my website!\n")
}
func getHello(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	fmt.Printf("%s: got /hello request \n", ctx.Value(keyServerAddr))

	myName := r.PostFormValue("myName")
	if myName == "" {

		w.Header().Set("x-missing-field", "myName")
		w.WriteHeader(http.StatusBadRequest)
		return

		// myName = "HTTP"
	}

	io.WriteString(w, fmt.Sprintf("Hello, %s!\n", myName))
}
func Server() {

	// with a server, you have to read the PORT env variabled assigned by the server
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080" //Fallback for local development if PORT is not set
	}
	jwtSecret = os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		fmt.Println("FATAL: JWT_SECRET is missing.")
		os.Exit(1)
	}
	// custom multiplexer
	// if you use the global router (http.DefaultServeMux), there is a high risk of name conflicts when different parts
	// of your application or external libraries try to register handlers for the same path.
	mux := http.NewServeMux()
	mux.HandleFunc("/", getRoot)
	mux.HandleFunc("/hello", getHello)
	mux.HandleFunc("/movie", FindMovieHandler)
	mux.HandleFunc("/insert", InsertMovieHandler)
	// NEW: Public route for obtaining the token
	mux.HandleFunc("/login", LoginHandler)
	// NEW: Protected route using the AuthMiddleware
	mux.HandleFunc("/profile", AuthMiddleware(ProfileHandler))

	// ctx, cancelCtx := context.WithCancel(context.Background()) // ctx is context.Context
	serverOne := &http.Server{ // initialize a struct
		// ctx := context.Background()
		// server := &http.Server{
		Addr:    ":" + port,
		Handler: mux,
		BaseContext: func(l net.Listener) context.Context {
			ctx := context.Background() // initalize a new context
			ctx = context.WithValue(ctx, keyServerAddr, l.Addr().String())
			return ctx
		},
	}
	// serverTwo := &http.Server{ // initialize a struct
	// 	Addr:    ":4444",
	// 	Handler: mux,
	// 	BaseContext: func(l net.Listener) context.Context {
	// 		ctx = context.WithValue(ctx, keyServerAddr, l.Addr().String())
	// 		return ctx
	// 	},
	// }

	// go func() {
	err := serverOne.ListenAndServe() // accept zero paraemter because it's not the same function from http.
	// start the server with ListenAndServe, the same as you have before, but this time you don’t need to provide parameters
	// to the function like you did with http.ListenAndServe because the http.Server values have already been configured.
	if errors.Is(err, http.ErrServerClosed) {
		fmt.Printf("server one closed\n")
	} else if err != nil {
		fmt.Printf("error listenting for server one: %s\n", err)
	}
	// cancelCtx()
	// }()

	// go func() {
	// 	err := serverTwo.ListenAndServe() // accept zero paraemter because it's not the same function from http.
	// 	// start the server with ListenAndServe, the same as you have before, but this time you don’t need to provide parameters
	// 	// to the function like you did with http.ListenAndServe because the http.Server values have already been configured.
	// 	if errors.Is(err, http.ErrServerClosed) {
	// 		fmt.Printf("server one closed\n")
	// 	} else if err != nil {
	// 		fmt.Printf("error listenting for server one: %s\n", err)
	// 	}
	// 	cancelCtx()
	// }()

	// () are there to immediately execute the anonymous function you defined.
	// The entire structure is a single, concise pattern used in Go to launch a function concurrently as a goroutine.

	// <-ctx.Done() // IS NOT NEEDED WHEN DEPLOYED ON A SERVER SUCH AS RENDER'S BECAUSE NOTHING SENDS CLOSE SIGNAL TO <-ctx.Done()
	// AND IT DOESN'T WAIT INDEFINITELY LIKE SIMLPLE BLOCKING CALL ListenAndServe() call does.

	// Because the go func() version is non-blocking, you need a way to tell the main thread to pause and wait.
	// This is where <-ctx.Done() comes in
	// moving two server out of goroutine will only let 1 server run since ListenAndServe() func is a blocking function by default

	// http.HandleFunc("/", getRoot) // sets up a handler function for a specific request path in the default server multiplexer
	// (look at a request path and call a given handler function associated with that path.).
	// http.HandleFunc("/hello", getHello)
	// When you use http.HandleFunc, you are telling this multiplexer:
	// "If a request comes in for this path, run this specific function."
	// When a user visits one specific URL, one function runs; when they visit the other URL, the second function runs.
	// err := http.ListenAndServe(":3333", mux) // pass nil to the second parameter (http.Handler) if you want to use the default server multiplexer
	// Because http.Handler is an interface, it’s possible to create your own struct that implements the interface.
	// http.ListenAndServe function, which tells the global HTTP server to listen for
	// incoming requests on a specific port with an optional http.Handler.
	// In your program, you tell the server to listen on ":3333". By not specifying an IP address before the colon,
	// the server will listen on every IP address associated with your computer,
	// and it will listen on port 3333. A network port, such as 3333 here, is a way for one computer to have many programs
	// communicating with each other at the same time.
	// Your http.ListenAndServe function also passes a nil value for the http.Handler parameter.
	// This tells the ListenAndServe function that you want to use the default server multiplexer and not the one you’ve set up.

	// if errors.Is(err, http.ErrServerClosed) { // The first error you’re checking for, http.ErrServerClosed,
	// 	// is returned when the server is told to shut down or close.
	// 	fmt.Printf("server closed\n")
	// } else if err != nil {
	// 	fmt.Printf("error starting server: %s\n", err)
	// 	os.Exit(1)
	// 	// In the second error check, you check for any other error. If this happens,
	// 	// it will print the error to the screen and then exit the program with an error code of 1 using the os.Exit function.
	// 	// If you see the address already in use error and you don’t have another copy of your program running,
	// 	// it could mean some other program is using it. If this happens, wherever you see 3333 mentioned in this tutorial,
	// 	// change it to another number above 1024 and below 65535, such as 3334, and try again.
	// }
}

// when the program is running in your terminal, you will need to open a second terminal to interact with your server.
// When you see commands or output with the same color as the command below, it means to run it in this second terminal.
// In this second terminal, use the curl program to make an HTTP request to your HTTP server.
// curl is a utility commonly installed by default on many systems that can make requests to servers of various types.
// For this tutorial, you’ll be using it to make HTTP requests. Your server is listening for connections on your computer’s port 3333,
// so you’ll want to make your request to localhost on that same port:

// In the output you’ll see the This is my website! response from the getRoot function,
// because you accessed the / path on your HTTP server.

// In this section, you created an HTTP server program, but it’s using the default server multiplexer and default HTTP server.
// Using default, or global, values can lead to bugs that are hard to duplicate because multiple parts of your program could be
// updating them at different and varying times.

// test commit
