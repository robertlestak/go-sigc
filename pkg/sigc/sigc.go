package sigc

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"

	"github.com/robertlestak/sigc/pkg/schema"
	log "github.com/sirupsen/logrus"
)

type KeyPair struct {
	PrivateKey []byte
	PublicKey  []byte
}

func GenerateRSAKeyPair() (KeyPair, error) {
	l := log.WithFields(log.Fields{
		"method": "GenerateRSAKeyPair",
	})
	var kp KeyPair
	l.Debug("generating RSA key pair")
	privatekey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		l.Error("error generating RSA key pair: " + err.Error())
		return kp, err
	}
	publickey := &privatekey.PublicKey

	// dump private key to file
	var privateKeyBytes []byte = x509.MarshalPKCS1PrivateKey(privatekey)
	privateKeyBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	}
	privBytes := pem.EncodeToMemory(privateKeyBlock)
	// dump public key to file
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publickey)
	if err != nil {
		l.Error("error marshalling public key: " + err.Error())
		return kp, err
	}
	publicKeyBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}
	pubBytes := pem.EncodeToMemory(publicKeyBlock)
	kp.PrivateKey = privBytes
	kp.PublicKey = pubBytes
	return kp, nil
}

func Sign(endpoint string, r *schema.SignRequest) (*schema.SignedRequest, error) {
	l := log.WithFields(log.Fields{
		"method": "Sign",
	})
	l.Debug("signing request")
	if len(r.PrivateKey) == 0 {
		kp, err := GenerateRSAKeyPair()
		if err != nil {
			l.Error("error generating RSA key pair: " + err.Error())
			return nil, err
		}
		r.PrivateKey = kp.PrivateKey
	}
	c := &http.Client{}
	jd, err := json.Marshal(r)
	if err != nil {
		l.Error("error marshalling request: " + err.Error())
		return nil, err
	}
	req, err := http.NewRequest("POST", endpoint+"/sign", bytes.NewBuffer(jd))
	if err != nil {
		l.Error("error creating request: " + err.Error())
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		l.Error("error sending request: " + err.Error())
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		l.Error("error signing request: " + resp.Status)
		return nil, err
	}
	var sr schema.SignedRequest
	err = json.NewDecoder(resp.Body).Decode(&sr)
	if err != nil {
		l.Error("error decoding response: " + err.Error())
		return nil, err
	}
	return &sr, nil
}

func Exec(endpoint string, r *schema.SignedRequest) (*schema.Response, error) {
	l := log.WithFields(log.Fields{
		"method": "Exec",
	})
	l.Debug("executing request")
	c := &http.Client{}
	jd, err := json.Marshal(r)
	if err != nil {
		l.Error("error marshalling request: " + err.Error())
		return nil, err
	}
	req, err := http.NewRequest("POST", endpoint+"/exec", bytes.NewBuffer(jd))
	if err != nil {
		l.Error("error creating request: " + err.Error())
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		l.Error("error sending request: " + err.Error())
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		l.Error("error executing request: " + resp.Status)
		return nil, err
	}
	var sr schema.Response
	err = json.NewDecoder(resp.Body).Decode(&sr)
	if err != nil {
		l.Error("error decoding response: " + err.Error())
		return nil, err
	}
	return &sr, nil
}
