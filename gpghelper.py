"""
--GPG Helper v0.1.0--

This project was started on 2020-11-01 UTC by 5a5a8.
Github: https://github.com/5a5a8
Email: 5a5a8@protonmail.com
PGP Public Key: https://keys.openpgp.org/vks/v1/by-fingerprint/020F9EEE6909D426FD1077AACE5FFC026D65B0F8

GPG Helper is a wrapper for GNU Privacy Guard (GPG).
GPG Helper is designed to make it easier for beginners to use GPG, so that access to privacy tools becomes more widespread.
A lot of more technical details are hidden from the user, and in some cases we reduce customisability in favour of ease of use.

5a5a8 is not affiliated with GPG.
GPG Website: https://gnupg.org
"""

import getpass
import io
import os
import re
import sys


class ManageKeys:
	"""Provides functions for key management; including generation, import, export, and delete"""

	def generate_new_key():
		"""Creates a new 4096 Bit RSA Keypair. It takes the options from the user, writes config to a temporary file,
		and then uses batch mode with 'gpg --batch --generate-key <config_file>'.
		The revocation certificate created by gpg is copied to the user's home directory."""
		
		
		Helpers.clear_screen()
		print('We are now going to generate a new key. This will be a 4096 bit RSA key.') 
		print('We need to collect some information from you.\n') 

		name_real = input('Enter your name: ')
		email_address = input('Enter your email address: ')
		passphrase = getpass.getpass('Enter a secure password: ')
		passphrase2 = getpass.getpass('Confirm your password: ')

		#if the passphases match, we can create the config file and generate the key
		#see https://www.gnupg.org/documentation/manuals/gnupg-devel/Unattended-GPG-key-generation.html 
		#for more information on what is happening here
		config_tempfile = os.getenv('HOME') + '/.GPGHelperTempConfigFile.tmp'
		if passphrase == passphrase2:
			with open(config_tempfile, 'w') as config: 
				config.write('Key-Type: RSA\n')
				config.write('Key-Length: 4096\n')
				config.write('Name-Real: ' + name_real + '\n')
				config.write('Name-Email: ' + email_address + '\n')
				config.write('Expire-Date: 0\n')
				config.write('Passphrase: ' + passphrase + '\n')
				config.write(r'%commit')
				config.close()
			
			#create the key and remove the temporary file - we redirect the output of gpg to a tempfile
			#this allows us to 1. get the location of the revocation certificate and copy the certificate to somewhere else
			#and 2. check for any errors and tell the user what they might have done wrong.
			#this is mostly handled by Helpers.run_system_command()
			Helpers.clear_screen()
			print('Generating key...\nThis can take a while.')
			gpg_output = Helpers.run_system_command('gpg --batch --generate-key ' + config_tempfile)
			Helpers.run_system_command('rm ' + config_tempfile)
			
			for line in gpg_output:
				matches = re.findall(r'(/home/.+([A-F0-9]{40}\.rev))', line)
				if matches:
					revocation_cert_dir = matches[0][0]
					revocation_cert_name = matches[0][1]
					Helpers.run_system_command('cp ' + revocation_cert_dir + ' ' + os.getenv('HOME') + '/' + revocation_cert_name)
					break
			if not matches:
				Helpers.hold_message('Something went wrong. Check your inputs and try again.')
				return
			
			print('\nNew key has been generated successfully.')
			print('\nWe have also generated a revocation certificate at ' + os.getenv('HOME') + '/' + revocation_cert_name)
			print('We strongly suggest you keep this somewhere safe (off-site) so that you don\'t lose it.')
			print('If your private key is compromised or lost, your revocation certificate is the only way to revoke your keys.')
			input('\n\nPress <ENTER> to Return')
			return


		else:
			Helpers.hold_message('The passphrases did not match.')
			return

		
	def import_key():
		"""Imports a key into the keyring from a given file.
		Uses 'gpg --import <filename>'"""

		Helpers.clear_screen()
		while True:
			print('A key will be imported from a file.\nThis can either be a .txt file or a .asc file.')
			key_file = input('\nEnter the name of the file containing the key, or enter Q to go back\n\n>>> ')
			if key_file.lower() == 'q': return

			working_dir = os.getcwd() 
			try:
				open(working_dir + '/' + key_file)
			except:
				Helpers.clear_screen()
				print('The file was not found. Check the file name and try again.\n')
				continue
			else:
				key_type = Helpers.run_system_command('gpg --show-keys ' + working_dir + '/' + key_file)

				#if it's public, go ahead and import it
				if key_type[0].startswith('pub'):
					gpg_output = Helpers.run_system_command('gpg --import ' + working_dir + '/' + key_file)

				#we need the passphrase to import a secret key
				elif key_type[0].startswith('sec'):
					passphrase = getpass.getpass('Enter the passphrase for the secret key: ') 
					cmd = 'gpg --pinentry-mode=loopback --passphrase "' + passphrase +'" --import ' + working_dir + '/' + key_file
					gpg_output = Helpers.run_system_command(cmd) 
					#print(gpg_output)
					#time.sleep(10)
				else:
					Helpers.hold_message('That didn\'t work. Maybe:\n\t1. The key is already imported.\n\t2. File is not valid')
					continue

				#check for success by looking at the gpg output for something like "name <email@example.com>" imported
				#or something like 'Bad passphrase'
				import_status = []
				for line in gpg_output:
					#there are a lot of problems here. I need to look into other solutions for scanning the output
					#maybe by joining everything into one line or checking the exit status of gpg
					#one such bug is user sees no output for already imported public key
					pub_match = re.findall(r'public key "(.+ <.+>)" imported', line)
					sec_match = re.findall(r'secret key imported', line)
					bad_pass = re.findall(r'error sending to agent: Bad passphrase', line)
					unchanged = re.findall(r'".+ <.+>" not changed', line)

					if pub_match or sec_match:
						import_status.append(line[5:])
					
					if bad_pass:
						Helpers.hold_message('Bad passphrase for private key.\nAssociated public key will be imported.')
					
				Helpers.hold_message( ''.join(import_status) )

					
	def get_email_and_fingerprint_from_index(keys_list: list, key_number: int) -> list:
		"""Takes a list of keys and an index number and returns the email address and fingerprint associated.
		The keys_list argument should be formatted keys from ManageKeys.get_table_of_keys()"""
		
		#each entry looks something like  "2:  RSA4096  2020-11-01 name1 name2 email@example.com 5BF4C2DE..."
		#so we can split it out and remove empty strings, and extract the email and fingerprint from the last two indices
		#then we can return the email and fingerprint to e.g.delete_key to delete the public key by its fingerprint
		#and confirm the email with the user
		key_found = False
		for key in keys_list:
			key_data = key.split(' ')
			while '' in key_data:
				key_data.remove('')
			index_of_key = int(key_data[0][:-1]) #remove the colon
			if index_of_key == int(key_number):
				key_email = key_data[-2]
				key_fingerprint = key_data[-1]
				key_found = True
				break
		if key_found == False:
			Helpers.hold_message('\nA key with that number was not found in the list of public keys. Please try again.\n')
			return []
		return [key_email, key_fingerprint]

	def get_table_of_keys(keys_data: list) -> list:
		"""Takes a list of keys from the output of gpg --list-keys and formats it nicely for our table"""

		#extract the data we want. each key is listed over 3 lines. the first line has the key_type and date_created
		#the second line has the fingerprint
		#the third line has the uid
		#TODO in later release: add support for further lines (subkeys)
		formatted_keys = []
		i = 0
		key_count = 0
		while i < len(keys_data): #TODO we can change to for loop since we now read every line
			if keys_data[i].startswith('pub') or keys_data[i].startswith('sec'): #to check the first line
				line = keys_data[i].split(' ')
				while '' in line:
					line.remove('')
				key_type = line[1].upper().ljust(13, ' ')
				date_created = line[2].ljust(15, ' ')
			
			match = re.findall(r'[A-F0-9]{40}', keys_data[i]) #to check the second line
			if match: fingerprint = match[0]

			if keys_data[i].startswith('uid'): #to check the third line
				#use a regex here in case the name has a space. the line is like
				#uid        [ultimate] name field <email@example.com>
				match = re.findall(r'\] (.+) <', keys_data[i])
				name = match[0].ljust(20, ' ')
				match = re.findall(r'<(.+)>', keys_data[i])
				email_address = match[0].ljust(30, ' ')
				key_count += 1
				key_str = str(key_count) + ': '.ljust(8, ' ') + key_type + date_created + \
																	' ' + name + ' ' + email_address + fingerprint
				formatted_keys.append(key_str)
			i += 1
		return formatted_keys



	def list_all_keys(pub: bool = True, sec: bool = True) -> list:
		"""Lists all of the available keys in the keyring.
		pub = True prints the public keys, sec = True prints the secret keys.
		Uses 'gpg --list-keys' for the public keys and 'gpg --list-secret-keys' for the private ones.
		The output from gpg is redirected to a temporary file and captured so it can be displayed in a user-friendly manner."""

		table_header = '\nNumber   Key Type     Date Created    Name                 Email Address '\
																		+ '                Fingerprint\n'

		if pub:
			print('The PUBLIC keys in your keyring are listed below.')
			print(table_header)

			#get the public keys. 
			public_keys_data = Helpers.run_system_command('gpg --list-keys')

			#output of gpg is not super beginner friendly, so we change it to something nicer
			formatted_public_keys = ManageKeys.get_table_of_keys(public_keys_data)
			for key in formatted_public_keys:
				print(key)


		#and again for the private keys 
		if sec:
			print('\n\nThe PRIVATE keys in your keyring are listed below.')
			print(table_header)

			private_keys_data = Helpers.run_system_command('gpg --list-secret-keys')

			formatted_private_keys = ManageKeys.get_table_of_keys(private_keys_data)
			for key in formatted_private_keys:
				print(key)
		
		if pub and sec:
			return [formatted_public_keys, formatted_private_keys]
		if pub and not sec:
			return [formatted_public_keys, None]
		if not pub and sec:
			return [None, formatted_private_keys]


	def delete_key():
		"""Deletes a key from the keyring.
		We delete the key by its fingerprint, to avoid problems with duplicate names or emails."""
		
		Helpers.clear_screen()
		while True:
			keys_list = ManageKeys.list_all_keys(pub=True, sec=True)
			public_keys = keys_list[0]
			private_keys = keys_list[1]
			del keys_list

			print('\n\nWhat would you like to do?\n\t1. Delete a Public Key\n\t2. Delete a Private Key\n\t3. (Q)uit\n')
			user_choice = input('Enter a number: ')

			if user_choice == '1': #delete a public key
				msg = 'Enter the number of the public key to be deleted: '
				key_email_fingerprint = Helpers.get_key_from_user(False, public_keys, private_keys, msg)
				
				if not key_email_fingerprint: 
					continue #the error message is handled by the get_email_and ... function
				else:
					key_email = key_email_fingerprint[0]
					key_fingerprint = key_email_fingerprint[1]
					del key_email_fingerprint

				#we need to check if a secret key exists for that fingerprint
				#gpg does not allow public key deletion if a private key exists for it
				private_key_exists = False
				for key_entry in private_keys:
					if key_fingerprint in key_entry:
						private_key_exists = True
						break

				if private_key_exists:
					Helpers.hold_message('A private key exists with that fingerprint.\nIt must be deleted first.')
					continue
					

				print('\nYou are about to delete <PUBLIC> key with email address: ' + key_email)
				print('\tAnd fingerprint: ' + key_fingerprint)
				continue_yn = input('\nY to continue, any other key to cancel: ')
				if continue_yn.lower() == 'y':
					Helpers.run_system_command('gpg --batch --yes --delete-keys ' + key_fingerprint)
					Helpers.hold_message('Key was deleted successfully.')
					continue
				else:
					Helpers.clear_screen()
					print('\nNo keys were deleted\n')
					continue
			
			elif user_choice == '2': #delete a private key
				msg = 'Enter the number of the private key to be deleted: '
				key_email_fingerprint = Helpers.get_key_from_user(True, public_keys, private_keys, msg)

				if not key_email_fingerprint: 
					continue #the error message is handled by the get_email_and ... function
				else:
					key_email = key_email_fingerprint[0]
					key_fingerprint = key_email_fingerprint[1]
					del key_email_fingerprint

				print('\nYou are about to delete <PRIVATE> key with email address: ' + key_email)
				print('\tAnd fingerprint: ' + key_fingerprint)
				continue_yn = input('\nY to continue, any other key to cancel: ')
				
				if continue_yn.lower() == 'y':
					Helpers.run_system_command('gpg --batch --yes --delete-secret-keys --fingerprint ' + key_fingerprint)
					Helpers.hold_message('Key was deleted successfully.')
					continue
				else:
					Helpers.hold_message('No keys were deleted.')
					

			elif user_choice == '3' or user_choice.lower() == 'q':
				return
			
			else:
				Helpers.hold_message('Input was not valid. Please try again.')
				continue

	def export_key():
		"""Exports a public or a private key as an ascii-armoured text file"""

		while True:
			Helpers.clear_screen()
			#We print all the keys and ask the user which one they want to export
			#We then have to get the fingerprint of that key from the list so that we can pass it to GPG for export
			#Using fingerprints means we won't have problems with duplicate emails

			public_keys, private_keys = ManageKeys.list_all_keys(pub = True, sec = True)


			#we have similar code if the key is public or private, so i have combined them into the same conditional flow 
			choice = input('\n\nWhat would you like to do?\n\t' +\
										'1. Export a Public Key.\n\t2. Export a Private Key.\n\t3. (Q)uit\n\n>>> ')
			if choice == '1' or choice == '2':
				if choice == '1': sec = False
				elif choice == '2': sec = True

				key_email_fingerprint = \
					Helpers.get_key_from_user(sec, public_keys, private_keys, 'Enter the number of the key to export: ')

				if not key_email_fingerprint:
					continue
				else:
					key_email = key_email_fingerprint[0]
					key_fingerprint = key_email_fingerprint[1]
					del key_email_fingerprint

				outfile = input('Enter the name of the file to write to (e.g. key.txt): ')

				#for public keys we can just go ahead and export
				if choice == '1': 
					Helpers.run_system_command\
						('gpg --output "' + outfile + '" --export --armor --fingerprint ' + key_fingerprint)

				#if it's a secret key, we need the passphrase
				elif choice == '2': 
					passphrase = getpass.getpass('Enter the passphrase for the key: ')
					
					cmd = 'gpg --pinentry-mode=loopback --output "' + outfile + '" --passphrase "' + passphrase +\
										'" --export-secret-key --armor --fingerprint ' + key_fingerprint
					
					#if success, gpg_output will be an empty list
					gpg_output = Helpers.run_system_command(cmd) 
					if gpg_output and 'Bad passphrase' in gpg_output[0]: 
						Helpers.hold_message('Passphrase was incorrect. Try again.')
						continue
					elif gpg_output: 
						Helpers.hold_message('Something went wrong. Try again.')
						continue

				Helpers.hold_message('Key with email: ' + key_email + '\nand fingerprint: ' + key_fingerprint +\
									'\nwas successfully written to file: ' + outfile)
				continue


			elif choice == '3' or choice.lower() == 'q':
				return
			else:
				Helpers.hold_message('Input was not valid. Please try again.')
				continue


	def show_main_page():
		"""Shows the main page for this class to the user so we can figure out what to do and call the appropriate functions."""

		Helpers.clear_screen()
		while True:
			print('Key Management\n\n\t1. (G)enerate New Key\n\t2. (I)mport Key\n\t3. (E)xport Key\n\t' +\
													'4. (L)ist All Keys\n\t5. (D)elete Key\n\t6. (B)ack To Menu\n\n')
			user_choice = input('>>> ')

			if user_choice == '1' or user_choice.lower() == 'g':
				ManageKeys.generate_new_key()
				Helpers.clear_screen()
			elif user_choice == '2' or user_choice.lower() == 'i':
				ManageKeys.import_key()
				Helpers.clear_screen()
			elif user_choice == '3' or user_choice.lower() == 'e':
				ManageKeys.export_key()
				Helpers.clear_screen()
			elif user_choice == '4' or user_choice.lower() == 'l':
				Helpers.clear_screen()
				ManageKeys.list_all_keys(pub=True, sec=True)
				input('\n\nPress <ENTER> to Return')
				Helpers.clear_screen()
				continue
			elif user_choice == '5' or user_choice.lower() == 'd':
				ManageKeys.delete_key()
				Helpers.clear_screen()
			elif user_choice == '6' or user_choice.lower() == 'b':
				return
			else:
				Helpers.clear_screen()
				print('Input was invalid. Please try again\n')
				continue



class EncryptPGP:
	"""Provides functions for encrypting messages and files"""
	
	def encrypt_file():
		"""Encrypts a user-specified file as armored ascii and outputs to a user specified file.
		Allows the user to specify multiple recipients"""

		Helpers.clear_screen()
		while True:
			infile = input('Enter the name of the file to encrypt, Q to quit: ')
			if infile.lower() == 'q': return
			try:
				open(infile, 'r')
			except:
				Helpers.hold_message('The file was not found. Please try again.')
				continue
			else:
				break

		outfile = input('Enter the name of the file to write the encrypted data to: ')

		recipient_keys = []
		while True:
			Helpers.clear_screen()

			public_keys = ManageKeys.list_all_keys(pub=True, sec=False)[0]
			msg = '\n\nEnter the numbers, one at a time, of the recipients to encrypt for.' +\
																					'\nEnter \'end\' when finished.\n\n>>> '

			pub_key = Helpers.get_key_from_user(False, public_keys, [], msg) #returns ['end'] if user inputs 'end'
			if pub_key == ['end']:
				break
			elif pub_key in recipient_keys or pub_key == []: #we skip duplicates and invalid inputs
				continue
			elif pub_key:
				recipient_keys.append(pub_key)

		#if we end up with an empty list, the user typed 'end' without entering any keys
		if not recipient_keys: return

		Helpers.clear_screen()
		print('File will be decryptable by the following users:\n')
		for key in recipient_keys:
			print('Email: ' + key[0].ljust(40, ' ') + '\tFingerprint: ' + key[1])
		while (continue_yn := input('\nIs this correct? (Y/N): ').lower()) not in ['y', 'n']:
			pass
		if continue_yn == 'n': return
		

		#otherwise, we can start building up our recipients string e.g --recipient <fingerprint> --recipient <fingerprint>
		#this will be used like gpg --encrypt ... ... --recipient ... --recipient ... --recipient ...
		#note that each key in recipients_keys is like [email, fingerprint]
		s_recipients = ''
		for key in recipient_keys:
			fingerprint = key[1]
			s_recipients += '--recipient ' + fingerprint + ' '

		cmd = 'gpg --output "' + outfile + '" --encrypt --armour --trust-model always ' + s_recipients + '"' + infile + '"'
		Helpers.run_system_command(cmd)

		Helpers.hold_message('<' + infile + '> encrypted and written to <' + outfile + '>')
		return


class DecryptPGP:
	"""Provides functions for decrypting messages and files"""


	def decrypt_file():
		"""decrypts files"""

		Helpers.clear_screen()

		#check for existence of secret keys before going ahead - if there are none, let's not waste user's time 
		#ManageKeys.list_all_keys returns a list of the keys, but also prints output, so we need to redirect stdout temporarily
		block_stdout = io.StringIO()
		sys.stdout = block_stdout
		sec_keys = ManageKeys.list_all_keys(pub=False, sec=True)[1]
		sys.stdout = sys.__stdout__

		if not sec_keys:
			Helpers.hold_message('There are no secret keys in your keyring, you cannot decrypt anything.')
			return

		#if we have keys, we can go ahead and get the infile and outfile from the user
		#then we can try to decrypt the infile
		while True:
			infile = input('Enter the name of the file to decrypt, Q to quit: ')
			if infile.lower() == 'q': return
			try:
				open(infile, 'r')
			except:
				Helpers.hold_message('File not found. Please try again.')
				continue
			else:
				break

		outfile = input('Enter the name of the file to write the decrypted data to: ')
		
		#we need to check who the data is encrypted for, and check that against the secret keys in the keychain.
		#if we use --list-packets and --pinentry-mode cancel, gpg prints out the ID of the keys
		#the ID is the same as the last 16 hex digits of the key fingerprint, which we can get from ManageKeys.list_all_keys()
		cmd = 'gpg --pinentry-mode cancel --list-packets "' + infile + '"'
		gpg_output = Helpers.run_system_command(cmd)
		key_ids = []
		for line in gpg_output:
			if 'no valid OpenPGP data' in line:
				Helpers.hold_message('File does not contain valid PGP data')
				return
			elif 'decrypt_message failed' in line:
				Helpers.hold_message('An error occurred. Is this a valid PGP encrypted file?')
			match = re.findall(r'ID ([0-9A-F]{16}),', line)
			if match: 
				key_ids.append(match[0])

		#now that we have the IDs of the keys the file was encrypted for, we can search for the same in our secret keys.
		#we don't just immediately try to decrypt because gpg will prompt for password, and i want to have everything text based.
		#we already have a list of the secret keys from when we checked if there were any at all.
		#sec keys is a list of strings, the end of each string contains the key fingerprint (of which the last 16 are the ID)
		match_found = False
		for key_id in key_ids:
			for sec_key in sec_keys:
				fingerprint_id = sec_key[-16:] 
				if fingerprint_id[-16:] == key_id: #the data can be decrypted with one of our private keys
					sec_key_split = sec_key.split(' ')
					match_found = True

					#extract email and fingerprint so we can ask user for passphrase
					while '' in sec_key_split:
						sec_key_split.remove('')
					fingerprint = sec_key_split[-1]
					email = sec_key_split[-2]

					break

		if not match_found:
			Helpers.hold_message('This data does not match any of your secret keys.\n' +\
									'If you think you might be a hidden recipient, enter a passphrase on the next screen.')
			passphrase = getpass.getpass('Enter a passphrase, or push <ENTER> to return: ')
			if passphrase == '':
				return

		elif match_found:
			Helpers.clear_screen()
			print('Enter the passphrase for key with email <' + email + '>\n\tand fingerprint: ' + fingerprint)
			passphrase = getpass.getpass('\nPassphrase: ')
		
		#finally, finally, finally, we can decrypt our data
		#this should work even with multiple private key matches, as gpg actually checks the passphrase against all secret keys
		cmd = 'gpg --output "' + outfile + '" --pinentry-mode loopback --passphrase "' + passphrase + '" --decrypt ' + infile
		gpg_output = Helpers.run_system_command(cmd)
		for line in gpg_output:
			if 'Bad passphrase' in line:
				Helpers.hold_message('Bad passphrase. Please try again.')
		Helpers.hold_message('<"' + infile + '"> decrypted and written to file <"' + outfile + '">')
		return
		

class SignPGP:
	"""Provides functions for signing messages"""
	
	def sign_file():
		"Takes a file as input and signs it with a clearsign signature"

		#we need to find out which secret key the user wants to sign the message with
		while True:
			Helpers.clear_screen()
			sec_keys = ManageKeys.list_all_keys(pub=False, sec=True)[1]
			msg = '\n\nEnter the number of the secret key you want to sign with, Q to quit: '
			key_email_fingerprint = Helpers.get_key_from_user(True, [], sec_keys, msg)
			if key_email_fingerprint == ['end']: return

			if not key_email_fingerprint:
				continue
			else:
				key_email = key_email_fingerprint[0]
				key_fingerprint = key_email_fingerprint[1]
				del key_email_fingerprint

			print('\nSign file using private key with email: ' + key_email + '\n\tAnd fingerprint: ' + key_fingerprint)
			continue_yn = input('\nContinue? (y/N): ')
			if continue_yn.lower() != 'y': continue
			
			passphrase = getpass.getpass('Enter the passphrase for the secret key: ')

			#currently we just read from a file and write to outfile, text editor support may be added in future
			infile = input('Enter the name of the file to sign: ')
			try:
				open(infile, 'r')
			except:
				Helpers.hold_message('The file was not found, please try again.')
				continue
		
			outfile = input('Enter the name of the file to write the signed data to: ')

			#we now have enough information to sign our file
			cmd = 'gpg --output "' + outfile + '" --local-user ' + key_fingerprint + ' --pinentry-mode loopback --passphrase "' + passphrase + '" --clearsign "' + infile + '"'
			gpg_output = Helpers.run_system_command(cmd)
			for line in gpg_output:
				print(line)
				if 'Bad passphrase' in line:
					Helpers.hold_message('Bad passphrase. Please try again.')
					continue
			Helpers.hold_message('<' + infile + '> signed and written to <' + outfile + '>')
			return
				
			




class VerifyPGP:
	"""Provides functions for verification of messages"""

	def verify_file():
		"""Verifies the signature on a file and lets the user know who signed it."""

		Helpers.clear_screen()
		while True:
			infile = input('Enter the the name of the file to verify, Q to quit: ')
			if infile.lower() == 'q': return
			try:
				open(infile, 'r')
			except:
				Helpers.hold_message('File not found. Please try again.')
				continue

			cmd = 'gpg --verify ' + infile
			gpg_output = Helpers.run_system_command(cmd)
			for line in gpg_output:
				match = re.findall(r'key ([A-F0-9]{40})', line)
				if match:
					fingerprint = match[0]
				match2 = re.findall(r'Good signature from ".+ <(.+)>"', line)
				if match2:
					email = match2[0]

			#if we don't find a fingerprint and email, we couldn't verify
			try:
				fingerprint + email
			except:
				Helpers.hold_message('The signature could not be verified.')
				return
			else:
				Helpers.hold_message('File contains a good signature from ' + email + ' with fingerprint: ' + fingerprint)
				return


class Helpers:
	"""Helper functions which do not directly relate to the main program behaviour,
	but which perform regularly used tasks."""

	def clear_screen():
		"""Clears the screen so we can have tidy output on each page"""

		os.system('clear')
		print('\n' * 3)

	def run_system_command(command: str) -> list:
		"""Runs a system command and returns the output as a list.
		Command should be in the form that would normally write to stdout.
		E.g. 'gpg --decrypt file.gpg' - this function handles redirecting output from stderr and stdout.
		Using this function means we don't have to load a bunch of temporary files and remember to remove them
		every time we want the output of a system command"""

		tempfile = os.getenv('HOME') + '/.GPGHelperTempFile.tmp'
		os.system(command + ' &> ' + tempfile)

		with open(tempfile, 'r') as f:
			cmd_output = f.readlines()
			f.close

		os.system('rm ' + tempfile)
		return cmd_output

	def hold_message(message: str = ''):
		"""'Halts' the program until the user pushes Enter, so that we may print some kind of notice"""
		
		Helpers.clear_screen()
		print(message)
		input('\n\nPress <ENTER> to Return')
		Helpers.clear_screen()

	def get_key_from_user(sec: bool, public_keys: list, private_keys: list, message: str) -> list:
		"""returns the email and fingerprint of a key selected by the user for the commonly used:
		'Enter the number of the key to ...' """


		key_number = input(message)

		#if we need to collect multiple keys from the user, we call this function in a loop until user types 'end'
		if key_number.lower() == 'end' or key_number.lower() == 'q':
			return ['end']

		try:
			int(key_number)
		except:
			Helpers.hold_message('Input was not a number. Try again.')
			return
		else:
			if sec == False:
				return ManageKeys.get_email_and_fingerprint_from_index(public_keys, key_number)
			elif sec == True:
				return ManageKeys.get_email_and_fingerprint_from_index(private_keys, key_number)

	def check_system() -> bool:
		"""returns true if system is posix and gpg is in path, to ensure compatability"""




def main():
	while True:
		Helpers.clear_screen()
		print('Welcome to GPG Helper Version 0.1.0\nWhat what you like to do?\n')
		print('\t1. (K)ey Management\n\t2. (E)ncrypt\n\t3. (D)ecrypt\n\t4. (S)ign\n\t5. (V)erify\n\t6. (Q)uit')
		user_input = input('\n>>> ')
		
		if user_input == '1' or user_input.lower() == 'k':
			ManageKeys.show_main_page()
		elif user_input == '2' or user_input.lower() == 'e':
			EncryptPGP.encrypt_file()
		elif user_input == '3' or user_input.lower() == 'd':
			DecryptPGP.decrypt_file()
		elif user_input == '4' or user_input.lower() == 's':
			SignPGP.sign_file()
		elif user_input == '5' or user_input.lower() == 'v':
			VerifyPGP.verify_file()
		elif user_input == '6' or user_input.lower() == 'q':
			return
		else:
			Helpers.hold_message('Input was invalid. Please try again.')

if __name__ == '__main__':
	main()





















