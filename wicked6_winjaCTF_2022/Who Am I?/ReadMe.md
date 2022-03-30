# Who Am I? 

The description for this challenge is simply an image:

![image](https://user-images.githubusercontent.com/10614967/160679315-c6e744c1-3c11-42b1-8408-79f2081a8293.png)

This was a fairly simple steganography challenge worth 146 points. It requires an understand of magic bytes in files.

## Solving the Challenge:

The only deliverable for this challenge is a file that Linux's file command identifies simply as "data"
```
knittingirl@DESKTOP-C54EFL6:/mnt/c/Users/Owner/Desktop/CTF_Files/wicked6_22$ file whoami
whoami: data
```
So, without much to go on, it makes sense to have a quick look at the file in a hex editor. I'm a big fan of HxD on Windows; Bless is also available for Linux. When I look at the file, I immediately notice strings like "sRGB", "gAMA", "IDAT", and more. These are common features of the header structure of a .png file.

![image](https://user-images.githubusercontent.com/10614967/160746493-1b40c420-1f69-4e48-b246-49e612f1840d.png)

This indicates that the steganography in this case probably involves fixing corrupted magic bytes in the file header. Here is a page that provides a good overview of magic bytes in the header and trailer of various file types:
https://www.garykessler.net/library/file_sigs.html

So, my first step is to fix the png header to make it match that on Gary Kessler's webpage, which, in hex, is "89 50 4E 47 0D 0A 1A 0A".

![image](https://user-images.githubusercontent.com/10614967/160747164-fb9a3428-9ab6-48cf-adb0-71d6ef64a366.png)

And it still doesn't open! To try to diagnose what was wrong, I decided to open a random sample .png file that wasn't broken and compare the hex. One thing that immediately caught my eye was the string "IHDR" where "FHES" is in the whoami file.

![image](https://user-images.githubusercontent.com/10614967/160747458-8c48ae96-5316-4668-9fc4-5108b2e9aba9.png)

So, I fixed that section in the hex editor as well:

![image](https://user-images.githubusercontent.com/10614967/160747641-a2c39fed-7d11-4334-ba35-5de95fe61733.png)

This time the file opens and I can see the flag!

![image](https://user-images.githubusercontent.com/10614967/160747740-2f3232ff-46d6-4767-9746-ec94b4e229ca.png)


Thanks for reading!
