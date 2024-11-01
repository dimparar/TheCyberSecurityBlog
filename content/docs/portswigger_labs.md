+++
title = 'PortSwigger Labs'
date = 2024-10-29T22:01:23+02:00
draft = false
showpage = true
+++



___

### Introduction



### Lab: Web shell upload via Content-Type restriction bypass
<br>

In this lab we have to exploit an upload vulnerability.

Go to "My account" and log in with the given credentials <br>

Username: wiener<br>
Password: peter

After logging in, we get redirected to "My account" page where there is an input box to upload our Avatar photo. <br>
![myaccount](lab1.png)
We want to check if there is any upload vulnerability we can exploit to get access to the server. For this cause we will use BurpSuite to analyze the POST request and response from the server.

By uploading a normal `.jpeg` file we are commanding a POST request:
![post_request](lab2.png)

Notice the `Content-Type: multipart/form-data;`. This means that for each input of the form we have seperate `Content-Disposision` and `Content-Type` headers.

If we try any file, other than `.jpeg` and `.png`, an error message is returned as response. So the server checks somehow the file we upload and its extension to make sure that it is an image.

There is a possibility that the server in order to read the extension of the file provided, uses the `Content-Type` header. In this case we could easily bypass this validation by keeping the `Content-Type: image/jpeg` and changing the file data into a php webshell that can give us Remote Command Execution (RCE).

Let's give it a try! Send the POST request to the Repeater and insert the payload like this:
![payload](lab3.png)
Send the request. The avatar picture was changed successfully!

Now let's refresh the "My account" page and then press `Ctrl+U` to open the source code. Open the avatar photo in order to run the `webshell.php`. Then add to the URL `?cmd=cat+/home/carlos/secret`.

Submit the code and voilla!

___

### Lab: File path traversal, simple case
<br>

Open the website along with BurpSuite Proxy to inspect the requests to the server. At the home page there are products for sale (Title, Image, Small Description). 

The image is probably stored locally at the server, so we should check if it vulnerable at path traversal attacks.

When we select a product we can see from BurpSuite Proxy the request `GET /product?productId=1`, with each product having each own ProductId. After this request there is another one, this time `GET /image?filename=53.jpg` for the image of the product.

Let's check if the second request is vulnerable to path traversal attacks.
Change the request with BurpSuite Repeater to 
```
GET /image?filename=../../../etc/passwd
```
![traversal_attack](lab4.png)
Success! The response contains the data from `/etc/passwd`.

___

### Lab: File path traversal, traversal sequences blocked with absolute path bypass
<br>

Open the website along with BurpSuite Proxy to inspect the requests to the server. At the home page there are products for sale (Title, Image, Small Description). 

The image is probably stored locally at the server, so we should check if it vulnerable at path traversal attacks.

When we select a product we can see from BurpSuite Proxy the request `GET /product?productId=1`, with each product having each own ProductId. After this request there is another one, this time `GET /image?filename=53.jpg` for the image of the product.

Usually all static content of a website is stored in a path like `var/www/images` at the server, so we want to exit this folder. If there is no validation or check then `../../../etc/passwd` should work.

Unfortunately, it's not working. Maybe the server treats the path given to `filename` parameter as an absolute path, so let's try giving `/etc/passwd`. Perfect, it just printed the `/etc/passwd` file contents in the reponse section of BurpSuite Repeater.

![attack](lab5.png)

Note: Try giving the absolute path of the file.

___

### Lab: File path traversal, traversal sequences stripped non-recursively
<br>

Same as before, open BurpSuite Proxy and send to Repeater the request `GET /image?filename=53.jpg`. This request is been commanded by the browser to load the image `53.jpg` which is stored in the server. Let's try some path traversal attacks.

```bash
# First try to exit var/www/images
../../../etc/passwd #Nope

# Now try Absolute Path
/etc/passwd #No Luck

# Server may have specific defences against path traversal attacks
# like removing suspicious characters (../)
....//....//....//etc/passwd #Success
```
![attack](lab6.png)

Even though the server removes all `../` characters, the remaining path is exactly what we want `../../../etc/passwd`.

___

### Lab: File path traversal, traversal sequences stripped with superfluous URL-decode
<br>

Same as before, open BurpSuite Proxy and send to Repeater the request `GET /image?filename=53.jpg`. This request is been commanded by the browser to load the image `53.jpg` which is stored in the server. Let's try some path traversal attacks.

```bash
# First try to exit var/www/images
../../../etc/passwd #Nope

# Now try Absolute Path
/etc/passwd #Nope

# Server may have specific defences against path traversal attacks
# like removing suspicious characters (../)
....//....//....//etc/passwd #Nope

# Use of URL Encoding
# %2e = .
# %2f = /
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd #Nope

# Double URL Encoding
# %25 = %
%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252Fpasswd #Success
```
![attack](lab7.png)

So in order to exploit this vulnearbility we need to encode our path traversal payload to Double URL Encoding.

___

### Lab: File path traversal, validation of start of path
<br>

Same as before, open BurpSuite Proxy and send to Repeater the request `GET /image?filename=53.jpg`. This request is been commanded by the browser to load the image `53.jpg` which is stored in the server. Let's try some path traversal attacks.

```bash
# First try to exit var/www/images
../../../etc/passwd #Nope

# Now try Absolute Path
/etc/passwd #Nope

# Server may have specific defences against path traversal attacks
# like removing suspicious characters (../)
....//....//....//etc/passwd #Nope

# Use of URL Encoding
# %2e = .
# %2f = /
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd #Nope

# Double URL Encoding
# %25 = %
%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252Fpasswd #Nothing

# Server could take the absolute path and validate the base URL
# For example here the absolute path is /var/www/images/53.jpg
# and the base URL is /var/www/images
/var/www/images/../../../etc/passwd #Success
```
![attack](lab8.png)

___

### Lab: File path traversal, validation of file extension with null byte bypass
<br>

Same as before, open BurpSuite Proxy and send to Repeater the request `GET /image?filename=53.jpg`. This request is been commanded by the browser to load the image `53.jpg` which is stored in the server. Let's try some path traversal attacks.

The methods from the other labs don't apply here. Maybe the server checks the extention of the file, so let's try to use `NULL` character to end the line before the `.jpg` to bypass the check. We need to use the URL encoded value `%00`.

```bash
../../../etc.passwd%00.jpg
```
![attack](lab9.png)

___
    
### Lab: Web shell upload via path traversal
<br>

Go to "My account" and log in with the given credentials <br>

Username: wiener<br>
Password: peter

After logging in, we get redirected to "My account" page where there is an input box to upload our Avatar photo. <br>

We want to check if there is any upload vulnerability we can exploit to get access to the server. For this cause we will use BurpSuite to analyze the POST request and response from the server.

Let's try to upload a `webshell.php` file (keep `Content-Type: image/jpeg`) in case the server uses it to identify the file extension.
![attack](lab10.png)

The response is 
![attack_response](lab11.png)

Refresh the page and press `Ctrl+U` for the source code of the "My account" page. The path of the file we uploaded is 
![path](lab12.png)

If go to this path, we get our payload printed to the screen without being executed. So we need to find a workaround to execute this file. The server problably has permitted executing files from the specific folder `/files/avatars` as a defensive mechanism.

If we send request with `filename="../webshell.php"`, we get as response `The file avatars/webshell.php has been uploaded.`. Notice that the path hasn't change regardless of `../`, so it problably filters the path ignoring parts that could lead to a path traversal attack.

There are many payloads we can use, other than just typing `../`. For example, let's try URL encoding `%2e%2e%2fwebshell.php` (equal to ../webshell.php).
As we can see now the response uploaded the file to `/avatars/../webshell.php`.

![path](lab13.png)

By opening the link we get a `Not Found` page. The URL is `web-security-academy.net/files/avatars/..%2fwebshell.php`, but if we remove `..%2f` then we will go to the path that we uploaded the file `web-security-academy.net/files/avatars/webshell.php`. It loads. Now let's see if the webshell works.

`web-security-academy.net/files/avatars/webshell.php?cmd=cat+/home/carlos/secret`

Sucess! We got the flag.

___

