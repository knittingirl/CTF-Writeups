# DecEivE 

The description provided for this challenge was simply an image: 
![image](https://user-images.githubusercontent.com/10614967/160674575-aa84b54b-199b-43e9-bf7e-8f862d083bb0.png)

This was a relatively easy cryptography challenge that was worth 138 points. It can be solved entirely using the CyberChef tool.

## Solving the Challenge: 

When we open up deceive.png, it appears to be a qr code. There are a lot of ways in which you could decode the contents, but one good option is CyberChef:

![image](https://user-images.githubusercontent.com/10614967/160677796-b88372cb-b8db-4ee3-8dca-4f58a57d0412.png)

So, at this point, we have the string "7=28L`0"#0r_560:D0v6}6#oE650U0#_E0cf0:D0FS65N". At this point, going from here to the flag may potentially require some trial-and-error. However, in general, when presented with some sort of enciphered string with no key or context, it is a great idea to throw it into CyberChef and try rotation variations of ROT13 and ROT47 (ROT13 will only rotate letters, while ROT47 will rotate all characters). In this case, the number 47 in the challenge description is also providing a nudge toward ROT47, and when we use that on our output, we get the flag.

![image](https://user-images.githubusercontent.com/10614967/160679045-26061b2b-4748-4f12-a738-cd125b1c435b.png)

Thanks for reading!
