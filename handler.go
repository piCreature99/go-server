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
	"strconv"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/golang-jwt/jwt/v5"
	// "os"

	// "bytes"
	// "encoding/base64"

	// Google Drive Imports
	"google.golang.org/api/drive/v3"
)

const keyServerAddr = "serverAddr"

// const jwtSecret = "Your_super_secret_and_log_key_here" // remember to use the secret from your env file later
var jwtSecret string

// MongoDB Document for Images
// Note: Storing Base 64 directly is simple but limited to 16MB per image.
type ImageRecord struct {
	ID          any       `bson:"_id" json:"-"` // MongoB unique ID
	EmployeeID  string    `bson:"employee_id" json:"employeeId"`
	Filename    string    `bson:"filename" json:"filename"`
	ImageBase64 string    `bson:"image_base64" json:"base64Data"` // THE IMAGE DATA
	CreatedAt   time.Time `bson:"created_at" json:"created_at"`
	UpdatedAt   time.Time `bson:"updated_at" json:"updated_at"`
}

// Global Drive Service variable (initialize this in main.go)
var DriveService *drive.Service

// 1. Request Payload (Matches your React Native JSON)
type UploadRequest struct {
	EmployeeID  string `json:"employeeId"`
	Filename    string `json:"filename"`
	ImageBase64 string `json:"imageBase64"` // Base 64 string
}

// 2. Response Payload
type UploadResponse struct {
	Success bool   `json:"success"`
	FileID  string `json:"fileId"`
}

// 3. MongoDB Document for Image (Optional: if you want to save metadata to DB)
type ImageMetadata struct {
	EmployeeID string    `bson:"employee_id"`
	Filename   string    `bson:"filename"`
	DriveLink  string    `bson:"drive_link"`
	FileID     string    `bson:"file_id"`
	CreatedAt  time.Time `bson:"created_at"`
}

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
	Username string `json:"username" bson:"username"`
	Password string `json:"password" bson:"password"`
	// You can add a Role field here for later use
	Role string `json:"role" bson:"role"`
}

// --- SYNCHRONIZATION STRUCTS ---
// 1. Incoming flattened row from the React Native app
type SQLiteRow struct {
	EmployeeID        int    `json:"employee_id"`
	Name              string `json:"name"`
	Role              string `json:"role"`
	Date              string `json:"date"`
	IsSynced          int    `json:"is_synced"`
	PresentState      int    `json:"present_state"`
	ConstructionState int    `json:"construction_state"`
	Remark            string `json:"remark"`
}

// 2. HTTP Request Body Payload
type SyncPayload struct {
	Records []SQLiteRow `json:"records"`
}

// 3. Final MongoDB Sub-Document for daily data
type DailyData struct {
	Date              string `bson:"date" json:"date"`
	IsSynced          int    `json:"is_synced"`
	PresentState      int    `json:"present_state"`
	ConstructionState int    `json:"construction_state"`
	Remark            string `json:"remark"`
}

// 4. Final MongoDB Employee Document Structure
type EmployeeDocument struct {
	ID        int         `bson:"_id" json:"_id"`   // Using _id employee_id for indexing/query efficiency
	Name      string      `bson:"name" json:"name"` // adding json tag help with field names from response returned to your app
	Role      string      `bson:"role" json:"role"`
	DailyData []DailyData `bson:"daily_data" json:"daily_data"`
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

// --- GET IMAGE HANDLER ---

func GetImageHandler(w http.ResponseWriter, r *http.Request) {

}

func DownloadImagesHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 1. Decode IDs we want to download
	var ids []string
	if err := json.NewDecoder(r.Body).Decode(&ids); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// 2. Query MongoDB for these IDs
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	filter := bson.M{"employee_id": bson.M{"$in": ids}}
	cursor, err := ImagesCollection.Find(ctx, filter) // return multiple document if the id matches
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	var results []ImageRecord
	if err = cursor.All(ctx, &results); err != nil {
		http.Error(w, "Decoding error", http.StatusInternalServerError)
		return
	}

	// 3. Send back the array of image data
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}

// --- UPLOAD IMAGE HANDLER ---

func UploadImageHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 1. Decode JSON Body
	var reqs []UploadRequest
	if err := json.NewDecoder(r.Body).Decode(&reqs); err != nil {
		http.Error(w, "Invalid JSON body (expected array)", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var processedIDs []string

	// 2. Loop through each image request
	for _, item := range reqs {
		// Strip base 64 prefix if exists
		base64Data := item.ImageBase64
		if idx := strings.Index(base64Data, ","); idx != -1 { // returns the index of comma, usually, images are send with a path like this:
			// data:image/jpeg;base64,/9j/4AAQSk...
			base64Data = base64Data[idx+1:]
		}

		// Basic validation
		if item.EmployeeID == "" || base64Data == "" {
			log.Printf("Skipping invalid record for EmployeeID: %s", item.EmployeeID)
			continue
		}

		// 3. Define the Filter (Find by EmployeeID)
		filter := bson.M{"employee_id": item.EmployeeID}

		// 4. Define the Update (Set new data)
		update := bson.M{
			"$set": bson.M{ // $set perform replacement if employee_id already exists
				"filename":     item.Filename,
				"image_base64": base64Data,
				"updated_at":   time.Now(),
			},
			"$setOnInsert": bson.M{ // subsequent updates won't overwrite the original creation date
				"created_at": time.Now(),
			},
		}

		// 5. Execute Upsert
		opts := options.UpdateOne().SetUpsert(true)
		_, err := ImagesCollection.UpdateOne(ctx, filter, update, opts)

		if err != nil {
			log.Printf("Upsert failed for %s: %v", item.EmployeeID, err)
			continue
		}

		processedIDs = append(processedIDs, item.EmployeeID)
	}

	// 6. Return Success Resposne
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":       true,
		"message":       "Bulk upsert completed",
		"Processed_ids": processedIDs,
		"count":         len(processedIDs),
	})

	// 6. Return Success Response
	// The InsertedID is returned as the underlying bson.ObjectID type (not the V1 path's preimitive.ObjectID)
	// The driver returns it as interface{}. The safest cast is to the concrete type it returned.

	// var insertedID string
	// if objectID, ok := insertResult.InsertedID.(primitive.ObjectID); ok{
	// 	// Safe to case to primitive.ObjectID (if the driver happens to resolve it this way)
	// 	insertedID = objectID.Hex()
	// } else if objectID, ok := insertResult.InsertedID.(bson.ObjectID); ok {
	// 	// Safe cast to bson.ObjectID (if the driver happens to solve it this way)
	// 	insertedID = objectID.Hex()
	// } else {
	// 	// Fallback for an unknown type (shouldn't happen)
	// 	log.Printf("Warning: InsertedID is not an ObjectID type: %T", insertResult.InsertedID)
	// 	insertedID = "" // Or use fmt.Sprint("%v", insertResult.InsertedID)
	// }

	// w.Header().Set("Content-Type", "application/json")
	// json.NewEncoder(w).Encode(UploadResponse{
	// 	Success: true,
	// 	FileID:  insertResult.InsertedID.(bson.ObjectID).Hex(), // Use bson.ObjectID for the cast
	// })

	// imageBytes, err := base64.StdEncoding.DecodeString(base64Data)
	// if err != nil {
	// 	log.Printf("Base64 decode error: %v", err)
	// 	http.Error(w, "Failed to decode image data", http.StatusBadRequest)
	// 	return
	// }

	// // 3. Prepare Drive File Metadata
	// // Define your folder ID here.
	// TARGET_FOLDER_ID := os.Getenv("FOLDER_ID")
	// log.Printf("DEBUG: FOLDER_ID retrieved is: [%s]", TARGET_FOLDER_ID)
	// f := &drive.File{
	// 	Name: req.Filename,
	// 	// Optional: Specify a folder ID to save into specific folder
	// 	Parents: []string{TARGET_FOLDER_ID},
	// }

	// // 4. Upload to Google Drive
	// // We convert the byte slice into a Reader for the Drive API
	// res, err := DriveService.Files.Create(f).Media(bytes.NewReader(imageBytes)).Do()
	// if err != nil {
	// 	log.Printf("Drive Upload Error: %v", err)
	// 	http.Error(w, "Failed to upload to Google Drive", http.StatusInternalServerError)
	// 	return
	// }

	// // 5. Make the File Public (Optional but recommended for easy downloading)
	// // This allows anyone with the link to download it, which simplifies your Sync Down logic

	// permission := &drive.Permission{
	// 	Type: "anyone",
	// 	Role: "reader",
	// }

	// _, err = DriveService.Permissions.Create(res.Id, permission).Do()
	// if err != nil {
	// 	log.Printf("Permission Error: %v", err)
	// 	// We continue even if permission fails, but log it
	// }

	// // 6. Get the WebContentLink (Direct Download Link)
	// // We need to fetch the file again to get specific fields like WebContentLink
	// fileInfo, err := DriveService.Files.Get(res.Id).Fields("webContentLink", "webViewLink").Do()
	// if err != nil {
	// 	log.Printf("Failed to get file link: %v", err)
	// 	http.Error(w, "Failed to retrieve link", http.StatusInternalServerError)
	// 	return
	// }

	// // 8. Return Success Response
	// w.Header().Set("Content-Type", "application/json")
	// json.NewEncoder(w).Encode(UploadResponse{
	// 	Success:   true,
	// 	DriveLink: fileInfo.WebContentLink, // This link is used for direct downloads
	// 	FileID:    res.Id,
	// })
}

// --- TRANSFORMATION UTILITY FUNCTION ---

// TransformData groups flat SQLiteRow data into the nested EmployeeDocument structure
func transformData(rows []SQLiteRow) []EmployeeDocument {
	// Map to hold EmployeeDocument pointers, keyed by EmployeeID
	employeeMap := make(map[int]*EmployeeDocument)
	// new concept: employeeMap return a copy, modifying it directly is useless, that's why you have to use pointer *EmployeeDocument
	// ex: employeeMap[row.EmployeeID].Name = "New Name" // error the map element is unaddressable, to modify without pointers:
	// 1. Get the current copy from the map
	// doc := employeeMap[row.EmployeeID]

	// // 2. Modify the copy (append data to the slice inside the copy)
	// doc.DailyData = append(doc.DailyData, dailyEntry)

	// // 3. Reassign the updated copy back into the map
	// employeeMap[row.EmployeeID] = doc // <-- REQUIRED STEP!
	for _, row := range rows {
		// 1. Initialize EmployeeDocument if not already in the map
		if _, ok := employeeMap[row.EmployeeID]; !ok { // ensures that you only create a new EmployeeDocument once per employee,
			// even if that employee has multiple daily records in the input slice.
			// if !ok, which mean not ok is false, creates the new EmployeeDocument and initializing base data (ID, Name, Role)
			// and the empty daily data slice
			employeeMap[row.EmployeeID] = &EmployeeDocument{ // use struct to assign data to a map
				ID:        row.EmployeeID,
				Name:      row.Name,
				Role:      row.Role,
				DailyData: make([]DailyData, 0), // Initialize the slice (array but better)
			}
		}

		// 2. Create the nested DailyData sub-document
		dailyEntry := DailyData{
			Date:              row.Date,
			IsSynced:          row.IsSynced,
			PresentState:      row.PresentState,
			ConstructionState: row.ConstructionState,
			Remark:            row.Remark,
		}

		// 3. Append the daily data to the employee's DailyData slice
		employeeMap[row.EmployeeID].DailyData = append(employeeMap[row.EmployeeID].DailyData, dailyEntry) // return a slice
		// employeeMap[row.EmployeeID] is a pointer to a struct, accessing data in this struct automatically dereference it,
		// assigning data directly modify the original struct's data, without the need of reassignment.
	}

	// 4. Convert map values back into a slice for BulkWrite
	// using map to check for duplicate id is faster and more efficient than slice
	var documents []EmployeeDocument
	for _, doc := range employeeMap {
		// *doc is a dereference
		documents = append(documents, *doc)
	}
	return documents
}

// --- DELETE HANDLER ---
func deleteEmployeeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete { // use delete method isntad of post because it correctly expresses the intent of your action and adheres
		// to established web standards, use the constant provided for less error prone
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 1. Get the MongoDB context and collection (assuming these are globally evaiable)
	// NOTE: You must replace 'mongoClient' and 'employeeCollection' with your actual variable names.
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// Assuming your collection variable is named 'employeesCollection;
	// collection := mongoClient.Database("your_database_name").Collection("employees")

	// 2. Extract the Employee ID from the URL path.
	// Assuming the URL format is /sync/employee/{id}
	// You'll need to update your router to handle this path variable.
	pathSegments := strings.Split(r.URL.Path, "/") // use use r.URL.Path instead of decoding the body because body is used for data creation and modification
	// not for deletion which is sent through the endpoint instead

	// Use the last non-empty segment, which should be the ID
	employeeIDsStr := pathSegments[len(pathSegments)-1] // this check for the last segment in the array

	// Input validation: ensure the ID segment exists
	if employeeIDsStr == "employee" || employeeIDsStr == "" {
		http.Error(w, "Missing employee ID in path (Expected /sync/employee/{id})", http.StatusBadRequest)
		return
	}
	// Split the comma-separated string into a slice of ID strings
	idStrings := strings.Split(employeeIDsStr, ",")

	// Convert the slice of strings to a slice of integers
	var employeeIDs []int // The slice to hold the final integer IDs
	for _, strID := range idStrings {
		// Trim whitespace for safety
		strID = strings.TrimSpace(strID)

		//Convert to integer
		intID, err := strconv.Atoi(strID)
		if err != nil {
			log.Printf("Invalid employee ID format received: %s in list %s", strID, employeeIDsStr)
			http.Error(w, "Invalid employee ID format in list", http.StatusBadRequest)
			return
		}
		employeeIDs = append(employeeIDs, intID)
	}
	// Input validation: ensure we have at least one ID
	if len(employeeIDs) == 0 {
		http.Error(w, "No valid emloyee IDs provided", http.StatusBadRequest)
		return
	}

	// 2. Call the bulk database logic function
	deletedCount, err := BulkDeleteEmployee(ctx, employeeIDs)

	if err != nil {
		log.Printf("MongoDB bulk deletion failed for ID %d: %v", employeeIDs, err)
		http.Error(w, "Failed to delete employees from cloud database", http.StatusInternalServerError)
		return
	}

	// 3. Optional Logging/Error handling for not found
	if deletedCount == 0 {
		// If the client requested deletion and it wasn't found, the client's goal
		// (to have the employee gone) is still achieved. We return 204.
		log.Printf("Employee ID %d not found in cloud database, but returning success.", employeeIDs)

		// 4. Send success response (204 No Content is standard for successful deletions)
		w.WriteHeader(http.StatusNoContent)
	}
}

// --- DOWNLOAD HANDLER ---

func DownloadDataHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if EmployeesCollection == nil {
		log.Println("MongoDB EmployeesCollection not initalized.")
		http.Error(w, "Server configuration error", http.StatusInternalServerError)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	// 1. Query MongoDB to find ALL employee documents
	filter := bson.D{} // Empty filter matches all documents

	// Find all documents
	cursor, err := EmployeesCollection.Find(ctx, filter)
	if err != nil {
		log.Printf("MongoDB Find error: %v", err)
		http.Error(w, "Internal server error during cloud query", http.StatusInternalServerError)
		return
	}

	defer cursor.Close(ctx) // Ensure the cursor is closed

	// 2. Decode all documents into a slice
	var employees []EmployeeDocument                   // EmployeeDocument is the struct you defined for MongoDB
	if err = cursor.All(ctx, &employees); err != nil { // write the result back to the memory location of the employee slice variable
		// for each document, it creates a new EmployeeDocument struct and appends it to the slice pointed to by &employee.
		log.Printf("MongoDB Cursor decoding error: %v", err)
		http.Error(w, "Internal server error during data processing", http.StatusInternalServerError)
		return
	}

	// 3. Send the JSON resposne
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	// Send the array of employee documents inside a wrapping object
	response := map[string]interface{}{
		"employees": employees,
		"message":   fmt.Sprintf("Retrieved %d employee documents from cloud.", len(employees)),
	}
	// returns structure similar to this:
	// {
	// "employees": [
	//     {
	//         "ID": 1,
	//         "Name": "John Doe",
	//         "Role": "Engineer",
	//         "DailyData": [
	//             { "Date": "2025-12-01", "IsSynced": 1, ... }
	//         ]
	//     },
	//     {
	//         "ID": 2,
	//         "Name": "Jane Smith",
	//         "Role": "Manager",
	//         "DailyData": [
	//             { "Date": "2025-12-01", "IsSynced": 1, ... }
	//         ]
	//     }
	// ],
	// "message": "Retrieved 2 employee documents from cloud."
	// }

	if err := json.NewEncoder(w).Encode(response); err != nil { // encodes into a json string and send it back to your application
		log.Printf("Error encoding JSON response: %v", err)
	}
}

// --- SYNCHRONIZATION HANDLER ---
func SyncDataHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 1. Decode the JSON payload
	var payload SyncPayload
	// NewDecoder reads the body and Decode for assigning data into the struct
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil { // pass in a pointer to the struct to modify its data directly
		log.Printf("Sync decode error: %v", err)
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	if len(payload.Records) == 0 {
		w.WriteHeader(http.StatusOK) // Sets the HTTP Status code and triggers header transmission
		// w represents the http.ResponseWriter interface. This interface is what your Go HTTP handler uses to build and send the response back to the client
		// the web browser or API consumer (w is write the response data and headers, r is for reading the incoming request data)
		// The general pattern:
		// 1. Set Headers First: Use w.Header().Set("Content-Type", "application/json") to set any custom headers.
		// 2. Set Status: Call w.WriteHeader(status) to finalize the headers and status line.
		// 3. Write Body Last: Use w.Write() or a JSON encoder (json.NewEncoder(w).Encode()) to send the actual data
		json.NewEncoder(w).Encode(map[string]string{
			"message": "No records provied to sync.",
		})
		return
	}

	// 2. Transform: Group the flat rows by Employee ID
	employeeDocuments := transformData(payload.Records)

	// 3. Load: Perform Bulk Upsert to MongoDB Atlas
	if EmployeesCollection == nil {
		log.Println("MongoDB EmployeesCollection not initialized.")
		http.Error(w, "Server configuration error", http.StatusInternalServerError)
		return
	}

	// Create a request context with a timeout

	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()

	var writes []mongo.WriteModel // interface. Represents a single atomic operation to be executed as part of a bulk write operation.
	// Serves as a generic container that allows you to mix different types of write operations (like, inserts, upates, and replacements)
	// into a single batch request to the MongoDB server.
	for _, doc := range employeeDocuments {
		// The upsert strategy here is to REPLACE the entire document with the new one.
		// This is simple but means the client must send ALL data for that employee ID.
		// For daily logs, a more advanced approach (using $addToSet or $push) might be needed
		// but for a full sync, ReplaceOne is fine.
		model := mongo.NewReplaceOneModel().
			SetFilter(bson.D{{Key: "_id", Value: doc.ID}}).
			SetReplacement(doc).
			SetUpsert(true) // Crucial: Insert if the document does not exist
		writes = append(writes, model)
		// this is basically insert and prevent duplication
	}

	// Perform the bulk operation
	result, err := EmployeesCollection.BulkWrite(ctx, writes)
	if err != nil {
		log.Printf("MongoDB Bulk Write Failed: %v", err)
		http.Error(w, "Failed to sync data to cloud database", http.StatusInternalServerError)
		return
	}

	// 4. Success Response
	log.Printf("Sync successful: Inserted/Updated %d documents.", result.UpsertedCount)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"message":       fmt.Sprintf("Sync complete. Total upserted/matched: %d", result.UpsertedCount+result.ModifiedCount),
		"upsertedCount": fmt.Sprintf("%d", result.UpsertedCount),
		"modifiedCount": fmt.Sprintf("%d", result.ModifiedCount),
	})
}

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
	expirationTime := time.Now().Add(120 * time.Minute)

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
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims) // this step let the server know about user role and exp time to validate returned tokens
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

			// Send  response to react native app (status 401 Unauthorized)
			http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
			return
		}

		// 3. If token is valid, execute the original handler (the 'next' function)
		next(w, r)
	}
}

func ProfileHandler(w http.ResponseWriter, r *http.Request) {
	// 1. Sets the Content-Type header so the client knows the body is JSON
	w.Header().Set("Content-Type", "application/json")

	// 2. Writes the actual response body to the client (the React Native app).
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
	// mux.HandleFunc("/sync/upload-data", AuthMiddleware(SyncDataHandler))
	mux.HandleFunc("/sync/upload-data", SyncDataHandler)
	mux.HandleFunc("/sync/download-data", DownloadDataHandler)
	mux.HandleFunc("/sync/employee/{id}", deleteEmployeeHandler)
	mux.HandleFunc("/api/upload", UploadImageHandler)
	mux.HandleFunc("/api/get", DownloadImagesHandler)

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
