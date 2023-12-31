/*
Author: Godwin Mercado ( Github: Goqwin)
Date: 25-12-2023
Description: This is a blockchain implementation in GoLang.
It is a simple blockchain that is used to store the transaction details of the users interacting with it,
it simulates a proof of work concept by using a nonce and a difficulty level to create a hash for the block.
The blockchain is also secured by using a Caesar Cipher and a set of keys to encrypt the data before creating the hash.
The blockchain is also secured by using a set of trusted proxies to secure the API.
*/

package main

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

/* Keys and Trusted Proxies are on an separate .env file for security purposes. You can add your own keys and trusted proxies to the .env file.
Below is the key I used based on the TV show Mr. Robot. I used the keys to encrypt the data and to create a hash for the blocks.
KEYS = Cybersecurity, hacktivism, encryption, vigilante, hacking, computer, programmer, fsociety, cybercrime, corporate, conspiracy, E Corp, digital world, code, technology, identity, mental illness, digital age, revolution, tech-savvy, digital fortress, hacker, cybernetic, dystopian, society, anonymity, malware, hacking tools, computer virus, zero-day, exploit, binary, algorithm, cyberattack, firewall, dark web, virtual, reality, motherboard, anarchy, decryption, data breach, digital symphony, chaos, control, power, digital identity, cyberpunk
*/

/*

Transaction Class: This class is used to store the transaction details of the user.
It contains the following fields:
User1 - The user who is initializing the interaction with the blockchain
Action - The action that the user is performing: Sent, Received, Bought, Sold
Amount - The amount of the cryptocurrency that is being transferred
Symbol - The symbol of the cryptocurrency that is being transferred
User2 - The user who is receiving the cryptocurrency from the user1 (We can also use this field to store the wallet address of the user1)

*/

type Transaction struct {
	User1  string  `json:"user1"`
	Action string  `json:"action"`
	Amount float64 `json:"amount"`
	Symbol string  `json:"symbol"`
	User2  string  `json:"user2"`
}

/*
Block Class: This class is used to store the block details of the blockchain.
It contains the following fields:
Index - The index of the block in the blockchain
Timestamp - The timestamp of the block when it was created
Transaction - The transaction details of the user
PreviousHash - The hash of the previous block in the blockchain
Hash - The hash of the current block in the blockchain
Nonce - The nonce of the current block in the blockchain
IsGenesis - A boolean value to check if the block is the genesis block or not
*/

type Block struct {
	Index        int
	Timestamp    string
	Transaction  Transaction
	PreviousHash string
	Hash         string
	Nonce        int
	IsGenesis    bool
}

/*
Blockchain Class: This class is used to store the blockchain details. (Of relationship between the blocks and blockchain)
It contains the following fields:
Blocks - An array of blocks that are present in the blockchain
*/

type Blockchain struct {
	Blocks []*Block
}

/*
AddBlockRequest Class: This class is used to store the request body of the POST request that is used to add a block to the blockchain.
It contains the following fields:
User1 - The user who is initializing the interaction with the blockchain
Action - The action that the user is performing: Sent, Received, Bought, Sold
Amount - The amount of the cryptocurrency that is being transferred
Symbol - The symbol of the cryptocurrency that is being transferred
User2 - The user who is receiving the cryptocurrency from the user1 (We can also use this field to store the wallet address of the user1)
*/

type AddBlockRequest struct {
	User1  string  `json:"user1"`
	Action string  `json:"action"`
	Amount float64 `json:"amount"`
	Symbol string  `json:"symbol"`
	User2  string  `json:"user2"`
}

// Global Variables
var usedCombinations = make(map[string]bool) // To store the used combinations of hashes and nonces to prevent duplicate hashes
var keys []string                            // To store the keys that are used to encrypt the data and create the hash this is used to prevent the hash from being cracked easily, so it retrieves from the .env file and splits the keys into an array
var lastUsedKey string
var blockchain *Blockchain

func loadEnvironment() {
	err := godotenv.Load()
	if err != nil {
		fmt.Println("Error loading .env file:", err)
	}
}

func getKeysFromEnv() {
	keysString := os.Getenv("KEYS")
	if keysString == "" {
		fmt.Println("WARNING: KEYS environment variable is not set. Using default key.")
		keys = []string{"protocol"}
	} else {
		keys = strings.Split(keysString, ",")
		fmt.Println("Keys have been loaded.")
	}
}

/* Caesar Cipher is used to encrypt the data before creating the hash
The Caesar Cipher implementation below takes the input string and shifts the characters by the shift value and returns the shifted string
the shifted value is dependent on the ASCII value of the character and the shift value, it is the key that is used to encrypt the data
*/

func CaesarCipher(input string, shift int) string {
	shifted := make([]byte, 0, len(input))
	for _, char := range input {
		shiftedChar := (int(char) + shift) % 126
		if shiftedChar < 32 {
			shiftedChar += 32
		}
		shifted = append(shifted, byte(shiftedChar))
	}
	return string(shifted)
}

/* EnhancedHash is used to create the hash of the block
The EnhancedHash implementation below takes the input string and the block and creates a hash based on the input string and the block
The hash is created by taking the ASCII value of each character in the input string and multiplying it by a prime number and adding the ASCII value of the next character
The hash is then converted to a hexadecimal value and the last used key is returned.
The Enhanced Hash also highlights the Avalanche Effect by using the keys to encrypt the data before creating the hash and the hash is also dependent on the previous hash.
*/

func EnhancedHash(input string, block Block) string {
	const prime = 31
	var hash uint32 = 0

	dataAndTimestamp := strconv.Itoa(block.Index) + block.Timestamp + input
	for _, char := range dataAndTimestamp {
		hash = hash*prime + uint32(char)
	}

	hash = hash & 0xFFFF
	if len(keys) == 0 {
		return ""
	}
	hashIndex := hash % uint32(len(keys))
	lastUsedKey = keys[hashIndex]

	return fmt.Sprintf("%04x", hash)
}

func NewBlock(transaction Transaction, prevHash string, index int, isGenesis bool) *Block {
	block := &Block{
		Index:        index,
		Timestamp:    time.Now().String(),
		Transaction:  transaction,
		PreviousHash: prevHash,
		Nonce:        0,
		IsGenesis:    isGenesis,
	}
	return block
}

/* calculateHash is used to calculate the hash of the block
The calculateHash implementation below takes the block and creates a hash based on the input string and the block
The hash is created by taking the ASCII value of each character in the input string and multiplying it by a prime number and adding the ASCII value of the next character
The hash is then converted to a hexadecimal value and the last used key is returned
*/

func (b *Block) calculateHash() string {
	input := b.Transaction.User1 + b.Transaction.Action + strconv.FormatFloat(b.Transaction.Amount, 'f', -1, 64) + b.Transaction.Symbol + b.Transaction.User2 + b.PreviousHash + strconv.Itoa(b.Nonce)
	return EnhancedHash(input, *b)
}

func (b *Block) mineBlock(difficulty int) {
	prefix := strings.Repeat("0", difficulty)
	uniqueHashFound := false

	for !uniqueHashFound {
		b.Hash = b.calculateHash()
		if strings.HasPrefix(b.Hash, prefix) {

			if _, exists := usedCombinations[b.Hash]; !exists {

				usedCombinations[b.Hash] = true
				uniqueHashFound = true
			}
		}
		b.Nonce++
	}
}

func NewBlockchain() *Blockchain {
	genesisTransaction := Transaction{
		User1:  "Genesis",
		Action: "Created",
		Amount: 0,
		Symbol: "",
		User2:  "",
	}

	genesisBlock := NewBlock(genesisTransaction, "", 0, true)
	genesisBlock.mineBlock(3)
	return &Blockchain{Blocks: []*Block{genesisBlock}}
}

func (bc *Blockchain) addBlock(user1, action string, amount float64, symbol, user2 string) error {
	mutex.Lock()
	defer mutex.Unlock()

	prevBlock := bc.Blocks[len(bc.Blocks)-1]
	transaction := Transaction{
		User1:  user1,
		Action: action,
		Amount: amount,
		Symbol: symbol,
		User2:  user2,
	}
	newBlock := NewBlock(transaction, prevBlock.Hash, prevBlock.Index+1, false)
	newBlock.mineBlock(2)

	bc.Blocks = append(bc.Blocks, newBlock)
	if !bc.isBlockValid() {
		bc.Blocks = bc.Blocks[:len(bc.Blocks)-1]
		fmt.Println("Invalid Block, blockchain validation failed.")
		return errors.New("Invalid Block, blockchain validation failed.")
	}

	fmt.Println("Block added successfully")
	fmt.Println("-------------------")
	fmt.Printf("New Block's Index: %d\n", newBlock.Index)
	fmt.Printf("New Block's Previous Hash: %s\n", newBlock.PreviousHash)
	fmt.Printf("New Block's Hash: %s\n", newBlock.Hash)
	return nil
}

func printBlockchain(bc *Blockchain) {
	fmt.Println("Blockchain:")
	fmt.Println("-------------------")

	for _, block := range bc.Blocks {
		inputForHash := block.Transaction.User1 + block.Transaction.Action + strconv.FormatFloat(block.Transaction.Amount, 'f', -1, 64) + block.Transaction.Symbol + block.Transaction.User2 + block.PreviousHash + strconv.Itoa(block.Nonce)

		_ = EnhancedHash(inputForHash, *block)

		fmt.Printf("Block Index: %d\n", block.Index)
		fmt.Printf("Timestamp: %s\n", block.Timestamp)
		fmt.Printf("User1: %s\n", block.Transaction.User1)
		fmt.Printf("Action: %s\n", block.Transaction.Action)
		fmt.Printf("Amount: %f\n", block.Transaction.Amount)
		fmt.Printf("Symbol: %s\n", block.Transaction.Symbol)
		fmt.Printf("User2: %s\n", block.Transaction.User2)
		fmt.Printf("Previous Hash: %s\n", block.PreviousHash)
		fmt.Printf("Hash: %s\n", block.Hash)
		fmt.Printf("Nonce: %d\n", block.Nonce)
		fmt.Printf("Key Used: %s\n", lastUsedKey)

		cipheredInput := CaesarCipher(block.Transaction.User1+block.Transaction.Action+strconv.Itoa(block.Index)+block.Timestamp+strconv.FormatFloat(block.Transaction.Amount, 'f', -1, 64)+block.Transaction.Symbol+block.Transaction.User2+block.PreviousHash+strconv.Itoa(block.Nonce), 2)
		fmt.Printf("Ciphered Input: %s\n", cipheredInput)
		fmt.Println("-------------------")
	}
}

// Console Operations for testing
func consoleOperations() {
	loadEnvironment()
	getKeysFromEnv()
	blockchain = NewBlockchain()
	fmt.Println("Creating a new blockchain...")
	blockchain.addBlock("David", "Sent", 10.0, "BTC", "Bob")
	blockchain.addBlock("Bob", "Sent", 5.0, "BTC", "Charlie")
	blockchain.addBlock("Charlie", "Sent", 3.0, "BTC", "David")
	blockchain.addBlock("David", "Sent", 7.0, "BTC", "Emily")
	fmt.Println("Printing the blockchain...")
	printBlockchain(blockchain)
}

// FOR ROUTERS AND RESTFUL API

var mutex = &sync.Mutex{}

func getBlockChain(c *gin.Context) {
	mutex.Lock()
	defer mutex.Unlock()
	c.JSON(http.StatusOK, gin.H{"Blockchain Fetched": blockchain})
}

func (bc *Blockchain) isBlockValid() bool {
	hashSet := make(map[string]bool)
	for b, block := range bc.Blocks {
		if b != 0 {
			if block.PreviousHash != bc.Blocks[b-1].Hash {
				return false
			}
		}
		if _, exists := hashSet[block.Hash]; exists {
			return false
		}
	}
	return true
}

func blockValidityCheck(c *gin.Context) {
	mutex.Lock()
	defer mutex.Unlock()
	isValid := blockchain.isBlockValid()
	if isValid {
		c.JSON(http.StatusOK, gin.H{"Message": "Blockchain is valid"})
	} else {
		c.JSON(http.StatusConflict, gin.H{"Validity": "Blockchain is invalid"})
	}
}

func addBlockToBlockchain(c *gin.Context) {
	var requestArray []AddBlockRequest
	if err := c.ShouldBindJSON(&requestArray); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	for _, requestBody := range requestArray {
		if err := blockchain.addBlock(requestBody.User1, requestBody.Action, requestBody.Amount, requestBody.Symbol, requestBody.User2); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		isValid := blockchain.isBlockValid()
		if !isValid {
			c.JSON(http.StatusConflict, gin.H{"Validity": "Blockchain is invalid"})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{"message": "Blocks added successfully"})
}

func main() {
	go consoleOperations()
	router := gin.Default()
	var trustedProxies []string // For securing your IP address - you can add your own IP address here to secure your API
	router.SetTrustedProxies(trustedProxies)
	router.GET("/blockchain", getBlockChain)
	router.GET("/blockchain/validity", blockValidityCheck)
	router.POST("/blockchain/add", addBlockToBlockchain)
	router.Run("localhost:8080")
}
