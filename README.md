# Stuffer

Stuffer is an application that allows you to embed hidden data into an image. It also supports asymmetric encryption and shuffling based on a seed

### Basic usage

Use this, if you want to share the data with everyone and do not care about detection

##### Encode
```
stuffer source_image.png input_data.tar output_image.png
```

##### Decode
```
stuffer -d source_image.png output_data.tar
```

Note that embedding data in image pixels will increase the size of the image file. However, the image with data and image without should look identical to the naked eye.

### Detection

By default, stuffer will store the data at the beginning of the pixel data, as well as a "tail" at the end, and that tail contains length of the data and SHA256 hash. This makes it relatively
easy to detect by websites who do not allow embedded data in images. If you wish to avoid that, there are some options

##### Shuffling

You can shuffle the data around using the -ss flag. This flag accepts a parameter, which is then hashed and used as a seed to random functions that are used for shuffling.
This parameter must also be known to everyone who wishes to retrieve the data from image.

Encoding example

```
stuffer -ss seed_value source_image.png input_data.tar output_image.png
```

Decoding example

```
stuffer -ss seed_value -d source_image.png output_data.tar
```

Shuffling is not meant to be used as a password however, for that use the built in asymmetric encryption support or encrypt the data beforehand.

##### No hash

Shuffling the data will under the hood also shuffle the least significant bits of all RGB colors in the image, which can cause the file size to grow further. If this is undesirable,
or you simply do not wish to use shuffle for other reasons, you can also use the -nh flag, which will cause the program to not calculate the checksum SHA256 hash. The hash will
therefore not be embedded inside the image, making detection harder, though not impossible. One can still look for magic bytes of common file types to detect embeded files automatically.
However, this will result in false positives. It also will not work on all file types. But generally this option is weaker than shuffling and therefore easier to detect.

Encoding example

```
stuffer -nh source_image.png input_data.tar output_image.png
```

Decoding example

```
stuffer -nh -d source_image.png output_data.tar
```

### Encryption

If you wish to send data to a specific person in a public forum, you can achieve this with the -k flag. It takes a parameter which is a path to RSA key, public key if encoding and private
key if decoding. Here is how you can generate these keys using command line utility openssl

##### Public key

```
openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048
```

##### Private key

```
openssl rsa -pubout -in private_key.pem -out public_key.pem
```

If you wish to send encrypted data inside the image to someone, you must first know his or her public key. After you have it, you can encode the data inside the image

```
stuffer -k public_key.pem source_image.png input_data.tar output_image.png
```

Then simply send the output_image.png to the recipient. If you are the recipient of such image, you can decode and decrypt it like this

```
stuffer -k private_key.pem -d source_image.png output_data.tar
```

The format of encrypted images is slightly different, it also stores timestamp and file extension, the former so that an attacker cannot resend old data to recipient
and pretend it is new data and the latter to make it easier for recipient to understand what the data contains. Since all of this data is encrypted, it doesn't increase
detectability. Nevertheless, you may still use the -ss and -nh flags in combination with the -k flag.