# UnityOs

CTF: Srdnlen CTF 2025\
Category: gamePwn\
Difficulty: Easy\
Author: Massimo Sanna [@SannaZ](https://github.com/Za9Game)

# Description

The challenge is a Unity game that tries do replicate an OS. The flag is inside an app inside the game, and to open it you must be sudo. 

# Solution

The description of the challenge gives a big hint: `It requires a lot of DLLs!`.  
Since the game is not compiled with IL2CPP, we can easily reverse it, so we open Assembly-CSharp.dll with dnSpy for example.  
Here we can see that the scripts that we are intersted in (the terminal's interpreter) are obfuscated. But opening them we can see that the strings aren't obfuscated.  
This way we can search for the word `sudo` and we can find this string: "You're sudo now!!!".  
Now we can easily follow the code flow in reverse, searching the number in the if, and following the call methods.  
We see that we are jumping in others dll, till we reach System.Sudo dll (of course it doesn't exist in standard build, it's a custom dll made by me)  
In this dll we can find the password to be sudo saved without obfuscation in the `MustBeSafeToSaveHere` structure.  
Now you won, you can go back in the game, use sudo command with the password found and open the `???` app.  
Hope you enjoed the game :)
