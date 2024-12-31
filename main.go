package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"flag"
	"fmt"
	"image"
	"image/png"
	"io"
	"math/rand"
	"os"
	"path/filepath"
)

type Program struct {
	verbose     bool
	doHash      bool
	decode      bool
	shuffleSeed string
	inputImage  string
	dataFile    string
	outputImage string
	keyFile     string
}

const HASH_SIZE = sha256.Size
const FSIZE_LEN = 4
const TIMESTAMP_LEN = 8
const RSA_SIZE = 256

func ShortUsage() {
	programName := "stuffer"
	if ex, err := os.Executable(); err == nil {
		programName = filepath.Base(ex)
	}
	fmt.Fprintf(os.Stderr, "%s is a program for embedding hidden data in images\n", programName)
	fmt.Fprintf(os.Stderr, "Encode usage: %s [flags] <input_image> <input_data_file> <output_image>\n", programName)
	fmt.Fprintf(os.Stderr, "Decode usage: %s [flags] <input_image> <output_data_file>\n", programName)
}

func ProgramFromArgs() *Program {
	p := &Program{}
	var noHash bool
	flag.BoolVar(&p.verbose, "v", false, "verbose output")
	flag.BoolVar(&noHash, "nh", false, "do not calculate the file hash")
	flag.BoolVar(&p.decode, "d", false, "decode the image instead of encode")
	flag.StringVar(&p.shuffleSeed, "ss", "", "shuffle seed, set this if you want to shuffle the data, also required when decoding")
	flag.StringVar(&p.keyFile, "k", "", "RSA key file. set this if you wish to encrypt the data. public key is used for encoding, private for decoding")
	flag.Parse()
	p.doHash = !noHash

	if p.decode {
		if flag.NArg() != 2 {
			ShortUsage()
			flag.Usage()
			if flag.NArg() > 0 {
				fmt.Fprintf(os.Stderr, "expected 2 required positional arguments <in_image> <out_data>. arguments got: %d\n", flag.NArg())
			}
			os.Exit(1)
			return nil
		}
		p.inputImage = flag.Arg(0)
		p.dataFile = flag.Arg(1)
	} else {
		if flag.NArg() != 3 {
			ShortUsage()
			flag.Usage()
			if flag.NArg() > 0 {
				fmt.Fprintf(os.Stderr, "expected 3 required positional arguments <in_image> <in_file> <out_image>. arguments got: %d\n", flag.NArg())
			}
			os.Exit(1)
			return nil
		}
		p.inputImage = flag.Arg(0)
		p.dataFile = flag.Arg(1)
		p.outputImage = flag.Arg(2)
	}
	return p
}

func (p *Program) run() error {
	if p.decode {
		return p.runDecode()
	} else {
		return p.runEncode()
	}
}

func (p *Program) runEncode() error {
	fInputImage, err := os.Open(p.inputImage)
	if err != nil {
		return err
	}
	defer fInputImage.Close()
	fData, err := os.Open(p.dataFile)
	if err != nil {
		return err
	}
	defer fData.Close()
	im, format, err := image.Decode(fInputImage)
	if err != nil {
		return fmt.Errorf("failed to read input image: %s", err.Error())
	}
	if p.verbose {
		fmt.Printf("read input image of format '%s'\n", format)
		fmt.Println("encoding ...")
	}
	if err = p.encodeImage(im, filepath.Ext(p.dataFile), fData); err != nil {
		return err
	}
	fOut, err := os.Create(p.outputImage)
	if err != nil {
		return err
	}
	defer fOut.Close()
	if err = png.Encode(fOut, im); err != nil {
		return fmt.Errorf("failed to encode output image: %s", err.Error())
	}
	fmt.Println("Success")
	return nil
}

func (p *Program) runDecode() error {
	fInputImage, err := os.Open(p.inputImage)
	if err != nil {
		return err
	}
	defer fInputImage.Close()
	fData, err := os.Create(p.dataFile)
	if err != nil {
		return err
	}
	defer fData.Close()
	im, format, err := image.Decode(fInputImage)
	if err != nil {
		return fmt.Errorf("failed to read input image: %s", err.Error())
	}
	if p.verbose {
		fmt.Printf("read input image of format '%s'\n", format)
		fmt.Println("decoding ...")
	}
	if err = p.decodeImage(im, fData); err != nil {
		return err
	}
	fmt.Println("Success")
	return nil
}

func (p *Program) decodeImage(im image.Image, data io.Writer) error {
	hiddenData, err := GetHiddenBytesFromImage(im)
	if err != nil {
		return fmt.Errorf("failed to get hidden data from image: %s", err.Error())
	}
	// handle shuffle seed
	if p.shuffleSeed != "" {
		if p.verbose {
			fmt.Println("unshuffling data")
		}
		indexes := make([]int, len(hiddenData))
		for i := range indexes {
			indexes[i] = i
		}
		passwordHash := sha256.Sum256([]byte(p.shuffleSeed))
		for i := 0; i < 4; i++ {
			seed := int64(binary.BigEndian.Uint64(passwordHash[(i * 8) : (i*8)+8]))
			r := rand.New(rand.NewSource(seed))
			r.Shuffle(len(indexes), func(i, j int) {
				indexes[i], indexes[j] = indexes[j], indexes[i]
			})
		}
		for newidx, oldidx := range indexes {
			for newidx != oldidx {
				hiddenData[newidx], hiddenData[oldidx] = hiddenData[oldidx], hiddenData[newidx]
				indexes[newidx], indexes[oldidx] = indexes[oldidx], indexes[newidx]
				oldidx = indexes[newidx]
			}
		}
	}

	// handle encryption case
	if p.keyFile != "" {
		if p.verbose {
			fmt.Println("decrypting data")
		}
		pos := len(hiddenData) - RSA_SIZE
		dataBlock, tailBlock := hiddenData[:pos], hiddenData[pos:]
		plainData, info, err := decryptDataWithRSA(p.keyFile, p.verbose, dataBlock, tailBlock)
		if err != nil {
			return err
		}
		fmt.Printf("decoding successful, got info:\nHash: %x\nExtension: %s\nTimestamp: %s\n", info.hash, info.extension, info.timestamp.String())
		if p.doHash {
			if p.verbose {
				fmt.Println("checking hash")
			}
			hashCmp := sha256.Sum256(plainData)
			if !bytes.Equal(info.hash, hashCmp[:]) {
				return fmt.Errorf("hash check failed (%x)", hashCmp)
			}
		}
		if n, err := data.Write(plainData); err != nil {
			return fmt.Errorf("failed to write data to the file (%d out of %d bytes written): %s", n, len(plainData), err.Error())
		}
		return nil
	}

	// length
	lenStart := len(hiddenData) - HASH_SIZE - FSIZE_LEN
	dataLength := binary.BigEndian.Uint32(hiddenData[lenStart : lenStart+FSIZE_LEN])
	if dataLength == 0 {
		return fmt.Errorf("data length is zero")
	}
	if dataLength > uint32(lenStart) {
		return fmt.Errorf("length is too large: %d > %d", dataLength, lenStart)
	}

	// hash check
	if p.doHash {
		if p.verbose {
			fmt.Println("checking hash")
		}
		checksum := sha256.Sum256(hiddenData[:dataLength])
		hashStart := len(hiddenData) - HASH_SIZE
		if !bytes.Equal(checksum[:], hiddenData[hashStart:]) {
			return fmt.Errorf("data hash verification failed")
		}
	}

	if n, err := data.Write(hiddenData[:dataLength]); err != nil {
		return fmt.Errorf("failed to write data to the file (%d out of %d bytes written): %s", n, dataLength, err.Error())
	}
	return nil
}

func (p *Program) encodeImage(im image.Image, extension string, data io.ReadSeeker) error {
	wi, ok := im.(WritableImage)
	if !ok {
		return fmt.Errorf("cannot edit the image pixels")
	}
	ibw, err := NewImageByteWriter(wi)
	if err != nil {
		return fmt.Errorf("failed to create image byte writer: %s", err.Error())
	}

	// get data size
	sz, err := data.Seek(0, io.SeekEnd)
	if err != nil {
		return fmt.Errorf("failed to get data size: %s", err.Error())
	}
	if sz < 0 || sz > int64(^uint32(0)) {
		return fmt.Errorf("invalid data size: %d", sz)
	}
	required := sz + HASH_SIZE + FSIZE_LEN
	var overhead int
	if p.keyFile != "" {
		// take into account additional data if encrypted
		if overhead, err = calculateRSAOverhead(); err != nil {
			return fmt.Errorf("failed to get AES128 gcm overhead: %s", err.Error())
		}
		required = sz + int64(overhead) + RSA_SIZE
	}

	if ibw.Capacity() < int(required) {
		return fmt.Errorf("image capacity is too small. require %dB, but only have %dB", required, ibw.Capacity())
	}
	if _, err = data.Seek(0, io.SeekStart); err != nil {
		return err
	}
	hiddenData, err := GetHiddenBytesFromImage(wi)
	if err != nil {
		return fmt.Errorf("failed to extract initial image data: %s", err.Error())
	}

	// copy data
	if n, err := io.ReadFull(data, hiddenData[:sz]); err != nil {
		return fmt.Errorf("failed to read desired data into a byte buffer (%d out of %d bytes read): %s", n, sz, err.Error())
	}
	// data size
	dataSize := sz
	sizePos := len(hiddenData) - HASH_SIZE - FSIZE_LEN
	binary.BigEndian.PutUint32(hiddenData[sizePos:sizePos+FSIZE_LEN], uint32(dataSize))
	// hash
	if p.doHash {
		hashPos := len(hiddenData) - HASH_SIZE
		checksum := sha256.Sum256(hiddenData[:sz])
		copy(hiddenData[hashPos:], checksum[:])
	}

	// encryption
	if p.keyFile != "" {
		if p.verbose {
			fmt.Println("encrypting data")
		}
		encdata, enctail, err := encryptDataWithRSA(p.keyFile, p.verbose, hiddenData[:sz], extension, hiddenData[sizePos:])
		if err != nil {
			return err
		}
		if len(encdata) > int(dataSize)+overhead {
			return fmt.Errorf("AES128 encrypted data is of size %d, which is larger than maximum expected size %d", len(encdata), dataSize+int64(overhead))
		}
		if len(enctail) != RSA_SIZE {
			return fmt.Errorf("RSA data is of size %d, not of expected size %d", len(enctail), RSA_SIZE)
		}
		copy(hiddenData[:len(encdata)], encdata)
		copy(hiddenData[len(hiddenData)-RSA_SIZE:], enctail)
	}

	// shuffle seed
	if p.shuffleSeed != "" {
		if p.verbose {
			fmt.Println("shuffling data")
		}
		// hash the password and calculate the random seed
		passwordHash := sha256.Sum256([]byte(p.shuffleSeed))
		for i := 0; i < 4; i++ {
			seed := int64(binary.BigEndian.Uint64(passwordHash[(i * 8) : (i*8)+8]))
			r := rand.New(rand.NewSource(seed))
			r.Shuffle(len(hiddenData), func(i, j int) {
				hiddenData[i], hiddenData[j] = hiddenData[j], hiddenData[i]
			})
		}
	}

	// write all of the data to the image
	if n, err := ibw.Write(hiddenData); err != nil {
		return fmt.Errorf("failed to write hidden data to the image (%d out of %d bytes written): %s", n, len(hiddenData), err.Error())
	}
	return nil
}

func main() {
	if err := ProgramFromArgs().run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
