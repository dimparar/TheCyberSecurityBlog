+++
title = 'PortSwigger Labs'
date = 2024-10-29T22:01:23+02:00
draft = false
showpage = true
+++

___
<h4 style="font-size:20px;font-weight: bold">
    Lab: Web shell upload via Content-Type restriction bypass
</h4>
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

<h4 style="font-size:20px;font-weight: bold">
    Lab: File path traversal, simple case
</h4>
<br>

Open the website along with BurpSuite Proxy to inspect the requests to the server. At the home page there are products for sale (Title, Image, Small Description). 

The image is probably stored locally at the server, so we should check if it vulnerable at path traversal attacks.

When we select a product we can see from BurpSuite Proxy the request `GET /product?productId=1`, with each product having each own ProductId. After this request there is another one, this time `GET /image?filename=53.jpg` for the image of the product.

Let's check if the second request is vulnerable to path traversal attacks.
Change the request with BurpSuite Repeater to 
```
GET /image?filename=../../../etc/passwd
```
![alt](lab4.png)
Success! The response contains the data from `/etc/passwd`.

___
