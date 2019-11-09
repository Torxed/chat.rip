from spiderWeb import spiderWeb
from os import urandom
from hashlib import sha512
from random import randint
import json

clients = {}
access_tokens = {}
chunks = {}

def gen_id(entropy_length=256):
	return sha512(urandom(entropy_length)).hexdigest()

class parser():
	def parse(self, client, data, headers, fileno, addr, *args, **kwargs):
		if 'payload' in data and 'access_token' in data:
			if not data['access_token'] in access_tokens:
				yield {'status' : 'failed', 'reason' : 'Invalid or expired access token.'}
				return

			sender_device_id = access_tokens[data['access_token']]
			partner_info = clients[sender_device_id]['connected_to']

			payload = {**data}
			del(payload['access_token'])
			sockets[partner_info['fileno']]['socket'].send(payload)

			yield {'status' : 'successful', 'transmission' : 'sent'}

		elif 'chunk' in data and 'access_token' in data:
			if not data['access_token'] in access_tokens:
				yield {'status' : 'failed', 'reason' : 'Invalid or expired access token.'}
				return

			sender_device_id = access_tokens[data['access_token']]
			partner_info = clients[sender_device_id]['connected_to']

			file_id = data['file_meta']['file_id']
			filename = data['file_meta']['name']

			payload = {**data}
			del(payload['access_token'])
			#print(' >> ', payload['chunk_id'])
			sockets[partner_info['fileno']]['socket'].send(payload)

			if not fileno in chunks:
				chunks[fileno] = {}
			if not filename in chunks[fileno]:
				chunks[fileno][filename] = {}
				for i in range(1, data['chunks']):
					chunks[fileno][filename][i] = False
			chunks[fileno][filename][data['chunk_id']] = True

			yield {'status' : 'successful', 'transmission' : 'sent', 'file_id' : file_id, 'filename' : filename, 'chunk' : data['chunk_id'], 'chunks' : data['chunks']}

		elif 'chunk_checksum' in data and 'access_token' in data:
			if not data['access_token'] in access_tokens:
				yield {'status' : 'failed', 'reason' : 'Invalid or expired access token.'}
				return

			filename = data['filename']
			missing = dict(filter(lambda elem: elem[1] == False, chunks[fileno][filename].items()))
			checksum = len(chunks[fileno][filename])-len(missing) >= data['chunk_checksum']
			print(f'Checking checksum for file {filename} [{checksum}]:', len(chunks[fileno][filename])-len(missing), data['chunk_checksum'])


			if checksum:
				del(chunks[fileno][filename])

			yield {'status' : 'successful', 'filename' : filename, 'checksum' : checksum, 'missing_chunks' : missing}

		elif 'connect' in data and 'access_token' in data:
			if not data['access_token'] in access_tokens:
				yield {'status' : 'failed', 'reason' : 'Invalid or expired access token.'}
				return
			if not data['connect'] in clients:
				yield {'status' : 'failed', 'reason' : 'Partner number not registered.'}
				return
			if data['connect'] == access_tokens[data['access_token']]:
				yield {'status' : 'failed', 'reason' : 'Can not connect to yourself, smartass! :)'}
				return
			if clients[access_tokens[data['access_token']]]['connected_to']:
				yield {'status' : 'failed', 'reason' : 'Already connected to a partner.'}
				return

			sender = access_tokens[data['access_token']]
			device_id = data['connect']
			partner_fileno = clients[device_id]['fileno']
			clients[sender]['connected_to'] = {'fileno' : partner_fileno, 'device_id' : device_id, 'state' : 'pending'}
			clients[device_id]['connected_to'] = {'fileno' : fileno, 'device_id' : sender, 'state' : 'pending'}

			sockets[partner_fileno]['socket'].send({
				'connection_from' : sender,
				'status' : clients[sender]['connected_to']['state']
			})

			yield {'status' : 'successful', 'connection' : clients[sender]['connected_to']['state'], 'partner' : data['connect']}
		elif 'accept' in data and 'access_token' in data:
			if not data['access_token'] in access_tokens:
				yield {'status' : 'failed', 'reason' : 'Invalid or expired access token.'}
				return

			sender = access_tokens[data['access_token']]
			if not clients[sender]['connected_to']['state'] == 'pending':
				yield {'status' : 'failed', 'reason' : 'Connection is not in a pending state.'}
				return
			if not clients[sender]['connected_to']['device_id'] == data['accept']:
				yield {'status' : 'failed', 'reason' : 'Invalid or expired partner ID.'}
				return

			device_id = data['accept']
			partner_fileno = clients[device_id]['fileno']

			clients[sender]['connected_to']['state'] = 'accepted'
			clients[device_id]['connected_to']['state'] = 'accepted'

			sockets[partner_fileno]['socket'].send({
				'connected_to' : sender,
				'status' : clients[device_id]['connected_to']['state'],
				'publicKey' : clients[sender]['publicKey']
			})

			yield {'status' : 'successful', 'connection' : clients[device_id]['connected_to']['state'], 'partner' : data['accept'], 'publicKey' : clients[device_id]['publicKey']}

		elif 'register' in data and data['register'] == 'publicKey':
			
			device_id = randint(1024, 9999)
			access_token = gen_id()
			while device_id in clients:
				device_id = randint(1024, 9999)

			access_tokens[access_token] = device_id
			clients[device_id] = {'publicKey' : data['keydata'], 'fileno' : fileno, 'connected_to' : None}

			yield {'status' : 'successful', 'device_id' : device_id, 'access_token' : access_token}

server = spiderWeb.server({'default' : parser()}, address='', port=6789)
