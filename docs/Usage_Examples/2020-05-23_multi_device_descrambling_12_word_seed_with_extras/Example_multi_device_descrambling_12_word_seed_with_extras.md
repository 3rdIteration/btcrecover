# "Required" Anchors, "Positional" Anchors and Spreading Work Accross Multiple Devices 
YouTube Video can be found here: TBC

## **Background**

In addition to being able to simply descramble a BIP39 seed using a tokenlist of potential words, BTCRecover can also be used in a situation where you may know the position of _some_ words while also having additional decoy words in a seed phrase. 

**Example tokenlist in use: tokenlist.txt**
``` linenums="1"
{% include "./tokenlist.txt" %}
```

For larger recovery jobs, BTCRecover also allows you to spread the workload over multiple devices. It's important to understand that the process that BTCRecover uses is **deterministic** what this means in simple terms is that every time you run BTCRecover, it will search through potential passwords/passphrases in exactly the same order, every single time. The implication of this is that simply running it on two devices at the same time, without using the --workers command, will simply be doing the identical work twice... 

Fortunately, you can split a search up into slices and assign these slices to different devices. The mechanism for this is extremely simple, basically assigning passwords in a "round robin" scheduling style. (eg: If the work is split up into three slices for three devices, each device will process every 3rd password) There is also the ability to assign multiple time slices to a single device in situations where one device may be multiple times faster than the others.

So let's consider the example of two devices, PC1 and PC2. In this example, PC1 is twice as powerful as PC2, so will be assigned 2/3 of the work, while PC2 will be assigned 1/3.

## Practical Limits
Working out how many potential passwords there are in a situation like this is quite straight forward.

For example, if you have a list of 20 words and know the postition of 3 of them within the 12 word seed, then there will be:

17 * 16 * 15 * 14 * 13 * 12 * 11 * 10 * 9 = 8,821,612,800 possible seeds (Very do-able in a few days depending on your CPU power available)

## Running BTCRecover

Both PCs will need BTCRecover installed and both use the identical command, with the exception of the --worker command which is different for each PC. (We can just ignore the fact that this tokenlist only produces a very small set to test) 

The devices don't need to be running the same operating system, nor do they need to communicate with each other in any way...

### Command on PC 1
So we want to assign work slices 1 and 2 to PC1

**Command**
```
python seedrecover.py --no-dupchecks --mnemonic-length 12 --language EN --dsw --wallet-type BIP39 --addr-limit 1 --addrs 17GR7xWtWrfYm6y3xoZy8cXioVqBbSYcpU --tokenlist ./docs/Usage_Examples/2020-05-23_multi_device_descrambling_12_word_seed_with_extras/tokenlist.txt
 --no-eta --worker 1,2/3
``` 

### Command on PC 2
And work slice 3 to PC2

**Command**
```
python seedrecover.py --no-dupchecks --mnemonic-length 12 --language EN --dsw --wallet-type BIP39 --addr-limit 1 --addrs 17GR7xWtWrfYm6y3xoZy8cXioVqBbSYcpU --tokenlist ./docs/Usage_Examples/2020-05-23_multi_device_descrambling_12_word_seed_with_extras/tokenlist.txt
 --no-eta --worker 3/3
```
 
### The Outcome...
 In this example, the correct seed phrase is found by PC2. Since there is no communication between the devices, PC1 will continue searching until it has exhausted the search space.
 
 This also highlights that you need to pay careful attention to what you are doing when using this command. If you accidentally forget to assign a work share to a PC, or assign the same shares twice, BTCrecover will have no way to know this has occured and no result will be found if the correct password would have occured in the untested share.
 
### Closing Thoughts
 Using the --no-eta command can be useful in situations like this as it will show you the current speed at which a device is checking passwords. It will also start immediately. (Which can be good if you are paying for cloud server time)
 
 One way that it an be useful to use this command is if you have already started a password search on your PC and know how many passwords will need to be checked, it can speed things up to run with --no-eta and just manually work out how long things will take.
 
 If you have started doing a seed recovery on a single device and want to move to a multi-device setup, but don't want to re-check the passwords already tested on a single device, you can take note of how many passwords the single device had tested and just use the --skip command when restarting the test across multiple devices.
 
 
  
