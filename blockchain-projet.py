import hashlib
import json
import requests
import base64

from time import time
from uuid import uuid4
from textwrap import dedent
from urllib.parse import urlparse

from flask import Flask, jsonify, request

from ecdsa import SigningKey, NIST384p

"""
each Block:
-an index
-a timestamp (in Unix time)
-a list of transactions
-a proof
-the hash of the previous Block 
"""

'''
Dictionaire de labo:
la cle du labo
les types de produits autorisés
'''


class Blockchain(object):
	def __init__(self):
		self.chain = []
		self.current_transactions = []

		self.none_used_transactions = []

		self.labs = dict()
		self.suppliers = dict()
		self.pharmas = dict()

		self.vacines = dict()
		self.products = set()

		self.public_keys = []

		#Create the genesis block
		self.new_block(previous_hash=1, proof=100)

		self.nodes = set()

	def add_lab(self,lab_key,signing_key,products_allowed):
		#key of lab ends with 0
		self.labs[lab_key] = [products_allowed,signing_key] 
		pass

	def add_suppliers(self,supplier_key,signing_key):
		#key of the supply ends with no 0
		self.suppliers[supplier_key] = signing_key
		#self.suppliers[supplier_key]["allowed"] = products
		pass

	def add_pharmas(self,pharma_key,signing_key):
		#key of the pharma ends with 00
		self.pharmas[pharma_key] = signing_key
		#self.pharmas[pharma_key]["allowed"] = vacines
		pass

	def add_vacines(self,vacines=dict()):
		d1 = dict()
		d1["vacine_1"] = dict()
		d1["vacine_1"]["ing1"] = 2
		d1["vacine_1"]["ing2"] = 1
		d1["vacine_1"]["ing3"] = 4

		d1["vacine_2"] = dict()
		d1["vacine_2"]["ing2"] = 2
		d1["vacine_2"]["ing4"] = 1
		d1["vacine_2"]["ing5"] = 4
		d1["vacine_2"]["ing6"] = 1

		d1["vacine_3"] = dict()
		d1["vacine_3"]["ing1"] = 1
		d1["vacine_3"]["ing2"] = 1
		d1["vacine_3"]["ing3"] = 1

		for v in d1:
			for i in d1[v]:
				if i not in self.products:
					self.products.add(i)
		z = d1.copy()
		z.update(vacines)
		self.vacines = z

	'''
	def inc_product(self,supplier,quantity):
		#if time%20==0:
		#for supplier in self.suppliers:
		for e,i in enumerate(self.suppliers[supplier]):
			self.suppliers[supplier[i]] += quantity[i]
	'''
	def new_block(self, proof, previous_hash=None):
		'''
		Creates a new Block in the Blockchain
		:param proof: <init> The proof given by the Proof of Work algo
		:param previous_hash: (Optional) <str> Hash of previous Block
		:return: <dict> New Block
		'''

		block = {
			'index': len(self.chain)+1,
			'timestamp': time(),
			'transactions': self.current_transactions,
			'proof': proof,
			'previous_hash': previous_hash or self.hash(self.chain[-1]),
		}
		#Reset the current list of transactions
		self.current_transactions = []

		self.chain.append(block)
		return block 

		
	@staticmethod
	def hash(block):
		'''
		Creates a SHA-256 hash of a Block
		:param block: <dict> Block
		:return: <str>
		'''
		#We must make sure that the Dictionary is Ordered, 
		#or we'll have inconsistent hashes 

		block_string = json.dumps(block,sort_keys=True).encode()
		return hashlib.sha256(block_string).hexdigest()
	
	@property
	def last_block(self):
		#Returns the last Block in the chain
		return self.chain[-1]

	@staticmethod
	def dict_to_binary(the_dict):
	    str = json.dumps(the_dict)
	    binary = ' '.join(format(ord(letter), 'b') for letter in str)
	    return binary

	def new_transaction(self, sender, recipient, amount):

		"""
		Creates a new transaction to go into the next mined Block
		:param sender: <str> Address of the Sender
		:param recipient: <str> Address of the Recipient
		:param amount: <int> Amount
		:return: <int> The index of the Block that will hold this transaction
		"""
		
		#sk = SigningKey.generate(curve=NIST384p) #private
		#vk = sk.verifying_key #public 
		
		if recipient[-1]!="0": #supplier
			sk = self.suppliers[int(recipient)]
		elif recipient[-2:]=="00": #pharma
			sk = self.pharmas[int(recipient)]
		else: #labs
			sk = self.labs[int(recipient)][1]

		#convert amount dictionary into a binary
		#message_amount = self.dict_to_binary(amount) 
		'''
		base64_bytes = base64.b64encode(message_bytes)
		base64_message = base64_bytes.decode('ascii')
		'''
		
		#message_amount = (json.dumps(amount)).encode("utf-8")

		message = json.dumps(amount)
		message_bytes = message.encode('ascii')
		message_amount = base64.b64encode(message_bytes)

		#print("\n",message_amount,"\n")
		#print("\n",b"message","\n")
		signature = sk.sign(message_amount)
		#signature_str = base64.b64decode(signature)
		#.decode("utf-8", "ignore")

		a_transaction = {
			'sender' : sender,
			'recipient': recipient,
			'amount' : amount,
			'signature': signature,
		}

		if sender=="0" and recipient[-1]!="0": #cannot send directly from 0 to labs or pharma:
			self.none_used_transactions.append(a_transaction)
			self.current_transactions.append(a_transaction)
			return self.last_block['index']+1

		else:
			if recipient[-2:]=="00": #received by a pharma
				amount_needed = self.trans_vacine_ing(a_transaction)
				amount_used ,new_none_used_transactions= self.update_used_transactions(a_transaction,amount_needed)
				if self.equivalent(amount_used,amount_needed):
					self.none_used_transactions = new_none_used_transactions
					self.current_transactions.append(a_transaction)
					return self.last_block['index']+1
				else:
					return -1


			else:
				amount_needed = a_transaction['amount']
				amount_used ,new_none_used_transactions= self.update_used_transactions(a_transaction,amount_needed)
				if self.equivalent(amount_used,amount_needed):#amount):#amount_used == amount:
					self.none_used_transactions = new_none_used_transactions

			#if self.equivalent(amount_used,amount) or sender=="0":
				
					self.none_used_transactions.append(a_transaction)
					self.current_transactions.append(a_transaction)
					return self.last_block['index']+1
				else:
					return -1
	'''
	def update_used_transactions(self,a_transaction):
		amount_used = 0
		sender = a_transaction['sender']
		recipient = a_transaction['recipient']
		amount = a_transaction['amount']
		new_none_used_transactions = []
		for transaction in self.none_used_transactions:

			if transaction['recipient']==sender and amount_used<amount:
				if transaction['amount']>(amount-amount_used):
					amount_added = amount-amount_used
					amount_used += amount_added
					amount_left = transaction['amount'] - amount_added
					new_transaction = {'sender':sender,'recipient':sender,'amount':amount_left}
					new_none_used_transactions.append(new_transaction)
				else:
					amount_added=transaction['amount']
					amount_used +=amount_added
			else:
				new_none_used_transactions.append(transaction)
		return amount_used, new_none_used_transactions
	'''

	def update_used_transactions(self,a_transaction,amount_needed):
		amount_used = dict()
		sender = a_transaction['sender']
		recipient = int(a_transaction['recipient'])
		signature = a_transaction['signature']
		#amount_needed = a_transaction['amount']
		new_none_used_transactions = []
		
		for ing in amount_needed:
			if recipient in self.labs and ing not in self.labs[recipient][0]:
				return dict(),[]
			amount_used[ing] = 0
		for transaction in self.none_used_transactions:
			if transaction['recipient']==sender and not self.equivalent(amount_used,amount_needed):
				amount_left = dict()
				for ing in transaction['amount']:
					
					amount_left[ing] = transaction['amount'][ing]
				
				for ing in amount_needed:
					if amount_used[ing]!=amount_needed[ing]:
						if ing in transaction['amount'] and (transaction['amount'][ing]>=amount_needed[ing]-amount_used[ing]):
							amount_added = amount_needed[ing]-amount_used[ing]
							amount_used[ing] += amount_added
							amount_left[ing] = transaction['amount'][ing]-amount_added
				#if not empty transaction
				empty = True
				for ing in amount_left:
					if amount_left[ing]!=0:
						empty = False
						break
				if not empty:
					new_transaction = {'sender':sender,'recipient':sender,'amount':amount_left,'signature':signature}
					new_none_used_transactions.append(new_transaction)
			else:
				new_none_used_transactions.append(transaction)
		return amount_used, new_none_used_transactions


	def trans_vacine_ing(self,a_transaction):
		amount_needed = dict()
		for vac in a_transaction['amount']:
			times = a_transaction['amount'][vac]
			print(vac,self.vacines,"\n")
			for ing in self.vacines[vac]:
				if ing not in amount_needed:
					amount_needed[ing] = self.vacines[vac][ing]*times
				else:
					amount_needed[ing] += self.vacines[vac][ing]*times
		return amount_needed 
	

	def equivalent(self,a1,a2):
		if len(a1)!=len(a2):
			return False
		for i in a1:
			if a1[i]!=a2[i]:
				return False
		return True



	def proof_of_work(self,last_proof):


		'''
		valider le labo avec le dictionaire .....
		'''

		'''
		Simple Proof of Work Algorithm:
		- Find a number p' such that hash(pp') contains leading 4 zeroes, where p is the previous p'
		- p is the previous proof, and p' is the new proof
		:param last_proof: <init>
		:return: <init>
		'''
		proof = 0
		while self.valid_proof(last_proof, proof) is False:
			proof+=1
		return proof 
	
	@staticmethod
	#static methods are like class methods, 
	#but they are bound to the class rather than its objects
	#they don't require a class instance creation so they are not dependent on the state of the object
	def valid_proof(last_proof, proof):
		'''
		Validates the Proof: Does hash(last_proof, proof) contain 4 leading zeroes?
		:param last_proof: <init> Previous Proof
		:param proof: <init> Current Proof
		:return: <bool> True if correct, False if not.
		'''
		fString =f"{last_proof}{proof}"
		guess = fString.encode()
		guess_hash = hashlib.sha256(guess).hexdigest()
		return guess_hash[:4] == "0000"

	def register_node(self,address):
		'''
		Add a new node to the list of nodes
		:param address: <str> Address of node. Eg. 'http://192.168.0.5:5000'
		:return: None
		'''
		parsed_url = urlparse(address)
		self.nodes.add(parsed_url.netloc)

	def valid_chain(self, chain):
		"""
		Determine if a given blockchain is valid 
		:param chain: <list> A blockchain
		:return: <bool> True if valid, False if not
		"""
		last_block = chain[0]
		current_index = 1

		while current_index<len(chain):
			block = chain[current_index]
			print(f'{last_block}')
			print(f'{block}')
			print("\n---------\n")

			#Check that the hash of the block is correct
			if block['previous_hash'] != self.hash(last_block):
				return False

			#Check that the Proof of Work is correct 
			if not self.valid_proof(last_block['proof'],block['proof']):
				return False

			last_block=block
			current_index +=1

		return True
	def resolve_conflicts(self):
		"""
		This is our Concensus Algorithm, it resolves conflicts 
		by replacing our chain with the longest one in the network.
		:return: <bool> True if our chain was replaced, False if not
		"""
		neighbours = self.nodes
		new_chain = None

		#We're only looking for chains longer than ours
		max_length = len(self.chain)

		#Grab and verify the chains from all the nodes in our network
		for node in neighbours:
			response = requests.get(f'http://{node}/chain')

			if response.status_code == 200:
				length = response.json()['length']
				chain = response.json()['chain']

				# Check if the length is longer and the chain is valid
				if length > max_length and self.valid_chain(chain):
					max_length = length
					new_chain = chain
		#Replace our chain if we discovered a new, valid chain longer than ours
		if new_chain:
			self.cahin = new_chain
			return True
		return False



# Instantiate our Node
app = Flask(__name__)
#Generate a globally unique address for this node
node_identifier = str(uuid4()).replace('-','')
#Instantiate the Blockchain
blockchain = Blockchain()

#lab1 
lab_key1 = 20
sk1 = SigningKey.generate(curve=NIST384p)
products_allowedl1 = ["ing1","ing2","ing3"]
blockchain.add_lab(lab_key1,sk1,products_allowedl1)
blockchain.public_keys.append(sk1.verifying_key)

#supplier 0 of all goods
supplier_key0 = 0
sk0 = SigningKey.generate(curve=NIST384p)
blockchain.add_suppliers(supplier_key0,sk0)
blockchain.public_keys.append(sk0.verifying_key)
#supplier1
supplier_key1 = 1
sk2 = SigningKey.generate(curve=NIST384p)
blockchain.add_suppliers(supplier_key1,sk2)
blockchain.public_keys.append(sk2.verifying_key)
#pharma1 
pharma_key1 = 300
sk3 = SigningKey.generate(curve=NIST384p)
blockchain.add_pharmas(pharma_key1, sk3)
blockchain.public_keys.append(sk3.verifying_key)

blockchain.add_vacines()




@app.route('/mine', methods=['GET']) #getting data
def mine():
	#mine if there are transactions

	#We run the proof of work algorithm to get the next proof...
	last_block = blockchain.last_block
	last_proof = last_block['proof']
	proof = blockchain.proof_of_work(last_proof)

	#We must receive a reward for finding the proof
	#The sender is "0" to signify that this node has mined a new coin
	'''
	blockchain.new_transaction(
		sender = "0",
		recipient=node_identifier, #recipient of the mined block is the address of the node
		amount=1,
	)
	''' 


	

	#Forge the new Block by adding it to the chain
	
	previous_hash = blockchain.hash(last_block)
	block = blockchain.new_block(proof, previous_hash)

	#check signatures
	allVerified = True
	for t in block['transactions']:
		verified_transaction = False
		sender = t['sender']
		recipient = t['recipient']
		amount = t['amount']
		signature = t['signature']

		message = json.dumps(amount)
		message_bytes = message.encode('ascii')
		message_amount = base64.b64encode(message_bytes)
	
		for vk in blockchain.public_keys:
			print("vk",vk,"\n")
			print("signature",signature,"\n")
			print("message_amount",message_amount,"\n")
			if vk.verify(signature, message_amount):
				verified_transaction = True
		if not verified_transaction:
			allVerified = False

		del t['signature']

	response = {
		'message' : "New Block Forged",
		'index' : block['index'],
		'transactions' : block['transactions'],
		'proof' : block['proof'],
		'previous_hash': block['previous_hash'],
	}

	if not allVerified:
		blockchain.chain.pop()
		#remove block from the chain
		response = {"New Block Not Forged"}
	

	
	

	return jsonify(response), 200

@app.route('/transactions/new',methods=['POST']) #sending data
def new_transaction():
	values = request.get_json()
	#Check that the required fields are in the POST'ed data
	required = ['sender','recipient','amount']
	if not all(k in values for k in required):
		return 'Missing values',400
	#Create a new Transaction
	index = blockchain.new_transaction(values['sender'],values['recipient'],values['amount'])
	
	if index>0:
		response = {'message':f'Transaction will be added to Block {index}'}
		#part2 = blockchain.none_used_transactions
		return jsonify(response), 201
	else:
		#part2 = blockchain.none_used_transactions
		response = {'message':f'Transaction will not be added to Block'}
		return jsonify(response), 201



@app.route('/chain',methods=['GET']) #returns the full Blockchain
def full_chain():
	response = {
		'chain': blockchain.chain,
		'length': len(blockchain.chain),
	}
	return jsonify(response),200

@app.route('/nodes/register', methods=['POST'])
def register_nodes():
    values = request.get_json()

    nodes = values.get('nodes')
    if nodes is None:
        return "Error: Please supply a valid list of nodes", 400

    for node in nodes:
        blockchain.register_node(node)

    response = {
        'message': 'New nodes have been added',
        'total_nodes': list(blockchain.nodes),
    }
    return jsonify(response), 201


@app.route('/nodes/resolve', methods=['GET'])
def consensus():
    replaced = blockchain.resolve_conflicts()

    if replaced:
        response = {
            'message': 'Our chain was replaced',
            'new_chain': blockchain.chain
        }
    else:
        response = {
            'message': 'Our chain is authoritative',
            'chain': blockchain.chain
        }

    return jsonify(response), 200

@app.route('/check/none_used_transactions', methods=['GET'])
def check():
    return jsonify(blockchain.none_used_transactions), 200

if __name__ == '__main__':
	app.run(host='0.0.0.0', port=5000) #runs the server on port 5000


