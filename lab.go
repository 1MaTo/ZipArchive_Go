package main

import (
	"bytes"
	"archive/zip"
	"io/ioutil"
	"log"
	"flag"
	"fmt"
	"os"
	"time"
	"gopkg.in/yaml.v2"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"github.com/fullsailor/pkcs7"
	"crypto/x509"
	"crypto/rsa"
	"encoding/pem"
	"path/filepath"
	"io"
	"strings"
)

type sFile struct{
	Name 			string 		`yaml:"name"`
	Original_Size 	uint32 		`yaml:"size"`
	Compressed_Size uint32 		`yaml:"compressed_size"`
	Mod_Time 		time.Time 	`yaml:"modify"`
	Hash 			string 		`yaml:"hash"`
}

type meta struct {
	File []sFile `yaml: "file"`
}

var metaData []sFile
var inc int =  0
var  modeFlag *string
var  pathFlag *string
var  certFlag *string
var  keyFlag *string
var  outputFlag *string
var hashFlag *string


func main() {

	modeFlag = flag.String("mode", "", "select mode")
	pathFlag = flag.String("path","","path to file")
	certFlag = flag.String("cert","./","path to certificate")
	keyFlag = flag.String("pkey","./","path to key")
	outputFlag = flag.String("output","archive.szip","path to archive")
	hashFlag = flag.String("hash","","hash")
	flag.Parse()

	switch *modeFlag {
	case "z":
		buf := new(bytes.Buffer)
		zipArchive := zip.NewWriter(buf)
		err := Archivate(*pathFlag, zipArchive, "");
		if err != nil {
			log.Printf(err.Error())
			return
		}
		err = zipArchive.Close()
		if err != nil {
			log.Printf(err.Error())
			return
		}
		ZipMetaFile, err := CreateMeta(metaData)
		if err != nil {
			log.Printf(err.Error())
			return
		}
		MainZip := new(bytes.Buffer)
		ml := make([]byte, 4)
		binary.LittleEndian.PutUint32(ml, uint32(ZipMetaFile.Len()))
		_, err = MainZip.Write(ml)
		if err != nil {
			log.Printf(err.Error())
			return
		}
		_, err = MainZip.Write(ZipMetaFile.Bytes())
		if err != nil {
			log.Printf(err.Error())
			return
		}
		_, err = MainZip.Write(buf.Bytes())
		if err != nil {
			log.Printf(err.Error())
			return
		}
		err = SignZip(*certFlag, *keyFlag, *outputFlag, MainZip)
		if err != nil {
			log.Printf(err.Error())
			return
		}

	case "x":
		err := Extract()
		if err != nil {
			log.Printf(err.Error())
			return
		}

	case "i":
		err := zipInfo()
		if err != nil {
			log.Printf(err.Error())
			return
		}
	}
}

func zipInfo()(error){
	sign, err := Verify()
	if err != nil {
		log.Printf(err.Error())
		return err
	} else {
		fmt.Println("Sign is verified")
	}
	if *hashFlag != "" {
		signer := sign.GetOnlySigner()
		if *hashFlag == strings.ToUpper(fmt.Sprintf("%x", sha1.Sum(signer.Raw))) {
			fmt.Println("Hashes are equal!")
		} else {
			fmt.Println("Hashes are not equal! Sing is broken")
		}
	}
	data := sign.Content
	buf, mlen, err := ReadMeta(data)
	if err != nil {
		log.Printf(err.Error())
		return err
	}
	mlen = mlen
	fmt.Printf(string(buf.Bytes()))
	return nil
}

func Extract() error {
	sign, err := Verify()
	if err != nil {
		return err
	}
	data, err := ioutil.ReadFile(*outputFlag)
	if err != nil {
		return err
	}
	if err != nil {
		return err
	}
	signer := sign.GetOnlySigner()
	if *hashFlag != "" {
		if *hashFlag == strings.ToUpper(fmt.Sprintf("%x", sha1.Sum(signer.Raw))) {
			fmt.Println("Hashes are equal!")
		} else {
			fmt.Println("Hashes are not equal! Sing is broken")
		}
	} else {
		fmt.Println("Hash of sign: " + strings.ToUpper(fmt.Sprintf("%x", sha1.Sum(signer.Raw))))
	}
	data = sign.Content
	buf, mlen, err := ReadMeta(data)
	if err != nil {
		return err
	}
	dzip := data[mlen+4:]
	yamlMeta := new(meta)
	err = yaml.Unmarshal(buf.Bytes(), yamlMeta)
	if err != nil {
		return err
	}
	r, err := zip.NewReader(bytes.NewReader(dzip), int64(len(dzip)))
	if err != nil {
		return err
	}
	var fm os.FileMode
	err = os.RemoveAll("extract")
	if err != nil {
		return err
	}
	err = os.Mkdir("extract", fm)
	if err != nil {
		return err
	}
	p := "./extract"
	i := 0
	for _, f := range r.File {
		dirs, _ := filepath.Split(f.Name)
		if f.ExternalAttrs == 0 {
			err = os.Mkdir(filepath.Join(p, dirs), fm)
			if err != nil {
				return err
			}
		} else {
			rc, err := f.Open()
			defer rc.Close()
			if err != nil {
				return err
			}
			file, err := os.Create(filepath.Join(p, f.Name))
			if err != nil {
				return err
			}
			defer file.Close()
			_, err = io.Copy(file, rc)
			if err != nil {
				return err
			}
			
			h := sha1.New()
			fileHash, err := ioutil.ReadFile(filepath.Join(p, f.Name))
			if err != nil {
				return err
			}
			h.Write(fileHash)
			hash := base64.URLEncoding.EncodeToString(h.Sum(nil))
			if hash == yamlMeta.File[i].Hash {
				fmt.Printf(f.Name + " hashes are equal\n")
			} else {
				fmt.Printf(f.Name + " hash is broken!\n")
			}
			i++
		}
	}
	return nil	
}

func ReadMeta(data []byte) (*bytes.Buffer, uint32, error) {
	mlen := binary.LittleEndian.Uint32(data[:4]) 
	bmeta := data[4 : mlen+4]                    

	m, err := zip.NewReader(bytes.NewReader(bmeta), int64(len(bmeta)))
	if err != nil {
		return nil, mlen, err
	}

	f := m.File[0]
	buf := new(bytes.Buffer)

	st, err := f.Open()
	if err != nil {
		return nil, mlen, err
	}
	_, err = io.Copy(buf, st)
	if err != nil {
		return nil, mlen, err
	}
	return buf, mlen, nil
}

func Verify() (sign *pkcs7.PKCS7, err error) {
	szip, err := ioutil.ReadFile(*outputFlag)
	if err != nil {
		return nil, err
	}
	sign, err = pkcs7.Parse(szip)
	if err != nil {
		return sign, err
	}
	err = sign.Verify()
	
	if err != nil {
		return sign, err
	}
	return sign, nil
}

func Archivate(path string, zipArchive *zip.Writer, dirName string) (error){
	files, err := ioutil.ReadDir(path)
	if err != nil {
		return err
	}
	md := new(sFile)
	for _, file := range files {
		fileInfo, err := os.Lstat(path + "/" + file.Name())
		if err != nil {
			return err
		}
		if (fileInfo.IsDir()){
			_, err := zipArchive.Create(filepath.Join(dirName,file.Name()) + "/")
			if err != nil {
				return err
			}
			err = Archivate(filepath.Join(path, file.Name()), zipArchive, filepath.Join(dirName, file.Name()) + "/")
			if err != nil {
				return err
			}
		} else { 
			fInfo, err := zip.FileInfoHeader(fileInfo)
			if err != nil {
				return err
			}
			fInfo.Name = dirName + fInfo.Name
			f, err := zipArchive.CreateHeader(fInfo)
			if err != nil {
				return err
			}
			data, err := ioutil.ReadFile(filepath.Join(path, file.Name()))
			if err != nil {
				return err
			}
			fillMeta(fInfo,data, md)
			_, err = f.Write([]byte(data));
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func SignZip(cert string, key string, Output string, zipFile *bytes.Buffer) (error) {
	signedData, err := pkcs7.NewSignedData(zipFile.Bytes())
	if err != nil {
		return err
	}
	certFile, err := ioutil.ReadFile(cert)
	certBlock, _ := pem.Decode(certFile)
	recpcert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return err
	}
	pkeyFile, err := ioutil.ReadFile(key)
	block, _ := pem.Decode(pkeyFile)
	parseResult, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return err
	}
	var recpkey *rsa.PrivateKey
	recpkey = parseResult.(*rsa.PrivateKey)
	signedData.AddSigner(recpcert, recpkey, pkcs7.SignerInfoConfig{})
	if err != nil {
		return err
	}
	detachedSignature, err := signedData.Finish()
	if err != nil {
		return err
	}
	sz, err := os.Create(Output)
	if err != nil {
		return err
	}
	defer sz.Close()
	_, err = sz.Write(detachedSignature)
	if err != nil {
		return err
	}
	return nil
}

func CreateMeta(met []sFile) (*bytes.Buffer, error) {
	var l meta
	l.File = met
	output, err := yaml.Marshal(l)
	if err != nil {
		return nil, err
	}
	MetaBuf := new(bytes.Buffer)
	zipMetaWriter := zip.NewWriter(MetaBuf)
	defer zipMetaWriter.Close()
	m, err := zipMetaWriter.Create("meta.yaml")
	if err != nil {
		return nil, err
	}
	_, err = m.Write(output)
	if err != nil {
		return nil, err
	}
	return MetaBuf, nil
}

func fillMeta(fileInfo *zip.FileHeader, file []byte, md *sFile){
	md.Name = fileInfo.Name
	md.Original_Size = fileInfo.UncompressedSize
	md.Compressed_Size = fileInfo.CompressedSize
	md.Mod_Time = fileInfo.ModTime()
	hash := sha1.New()
	hash.Write(file)
	md.Hash = base64.URLEncoding.EncodeToString(hash.Sum(nil))
	metaData = append(metaData, *md)
}