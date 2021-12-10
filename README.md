# PassGen
### An (almost) completely open source password generator and manager/keychain for those who live in the terminal

Your passwords should stay with you. Passgen never uploads anything to the cloud, or to anywhere on the internet for that matter. The only way people get your passwords from passgen is if you screw up.
We've made sure to use cryptologically secure random generators, safe loading from files, and aes-256 encryption on passwords stored.
In addition, your passwords are never kept in memory. From the time you generate your passwords to the time you retrieve them from your keychain they are kept encrypted and only decrypted when printing to the terminal.
Finally, your keychain is stored behind a password of your choosing, so no one can access your passwords just by hopping on your terminal.

You can use passgen in any way you want:
	- Purely as a password generator, passwords by default are never stored
	- Password manager, with functionality for:
		- Username
		- Password
		- Site tag
	- Password storage - you can give passgen as much or as little of your data as you want, meaning you can use another service to generate your passwords and just store them in passgen

The choice is yours!

## Usage
`python3 generator_code.py [OPTIONS]`

### Options:
	- `-l`, `--length` 			--> Length of outputted password, 18 by default
	- `-t`, `--tag` 			--> Adds the password's use to the keychain
	- `-u`, `--user` 			--> Adds the respective username for the password to the keychain
	- `-f`, `--find`			--> Finds previously generated passwords by tag if they have been stored in keychain
	- `-s`, `--save` 			--> Tells passgen to save the generated password (as well as other user data, if available) in keychain under aes-256 encryption. Deactivated by default!
	- `-i`, `--import_data`		--> Imports a previously created password (as well as other user data, if available) to the keychain
	- `-p`, `--password` 		--> Password flag, used only for importing externally created passwords

## Wishlist/To-Do
	- Pass phrases (instead of random characters)
	- 2FA
    - Installable on brew, gh-packages, snap, apt, etc.
    - improved search w/ regex for get_from_keychain (which needs to be fixed (i.e. `--find`))
    - multiple encryption options
    - multiple keychain file support
    - multiple keychain file type support

## Contributing
This is really mostly a passion project, but if you want to help please start a pull request and I'll get to it.
If you have any suggestions, all my contacts are on my (website)[jstr.dev] at the bottom. Send me an email or something.
  
