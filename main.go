package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/hashicorp/vault-plugin-auth-pcf/signatures"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"
)

// IndexHandler returns a printout of the request it received for debugging.
func IndexHandler(w http.ResponseWriter, r *http.Request) {
	endpoint := r.URL.Query().Get("endpoint")
	if endpoint == "" {
		endpoint = "/v1/auth/pcf/login"
	}
	vaultAddr := r.URL.Query().Get("vault_addr")
	if vaultAddr == "" {
		vaultAddr = "http://localhost:8200"
	}

	// Show what we're working with.
	pathToInstanceCert := os.Getenv("CF_INSTANCE_CERT")
	fmt.Println("CF_INSTANCE_CERT: " + pathToInstanceCert)
	certBytes, _ := ioutil.ReadFile(pathToInstanceCert)
	fmt.Printf("%s\n", certBytes)

	pathToInstanceKey := os.Getenv("CF_INSTANCE_KEY")
	fmt.Println("CF_INSTANCE_KEY: " + pathToInstanceKey)
	keyBytes, _ := ioutil.ReadFile(pathToInstanceKey)
	fmt.Printf("%s\n", keyBytes)

	signingTime := time.Now().UTC()
	signature, err := signatures.Sign(pathToInstanceKey, &signatures.SignatureData{
		SigningTime: signingTime,
		Role:        "test-role",
		Certificate: string(certBytes),
	})
	if err != nil {
		w.Write([]byte(err.Error()))
		w.WriteHeader(400)
		return
	}
	reqBody := map[string]interface{}{
		"role":         "test-role",
		"certificate":  certBytes,
		"signing_time": signingTime.Format(signatures.TimeFormat),
		"signature":    signature,
	}
	reqBodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		w.Write([]byte(err.Error()))
		w.WriteHeader(400)
		return
	}

	req, err := http.NewRequest(http.MethodPost, vaultAddr+endpoint, bytes.NewReader(reqBodyBytes))
	if err != nil {
		w.Write([]byte(err.Error()))
		w.WriteHeader(400)
		return
	}
	req.Header.Add("X-Vault-Token", "root")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		w.Write([]byte(err.Error()))
		w.WriteHeader(400)
		return
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(r.Body)
	w.Write(body)
	w.WriteHeader(resp.StatusCode)
}

func main() {
	http.HandleFunc("/login", IndexHandler)
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`I'm up!'`))
	})

	var port string
	if port = os.Getenv("PORT"); len(port) == 0 {
		port = "8080"
	}

	fmt.Println("starting on port " + os.Getenv("PORT"))
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
