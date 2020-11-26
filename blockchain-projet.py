import hashlib
import json
import requests

from time import time
from uuid import uuid4
from textwrap import dedent
from urllib.parse import urlparse

from flask import Flask, jsonify, request

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

		#Create the genesis block
		self.new_block(previous_hash=1, proof=100)

		self.nodes = set()

	def add_lab(self,lab_key,vacines,products_allowed):
		self.labs[lab_key] = dict()
		self.labs[lab_key]["vacines"] = vacines
		self.labs[lab_key]["allowed"] = products_allowed
		pass

	def add_suppliers(self,supplier_key,products):
		self.suppliers[supplier_key] = dict()
		self.suppliers[supplier_key]["allowed"] = products
		pass

	def add_pharmas(self,pharma_key, vacines):
		self.pharmas[pharma_key] = dict()
		self.pharmas[pharma_key]["allowed"] = vacines
		pass

	def vacines(self,vacines=None):
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

		return d1+vacines


	def inc_product(self,supplier,quantity):
		#if time%20==0:
		#for supplier in self.suppliers:
		for e,i in enumerate(self.suppliers[supplier]):
			self.suppliers[supplier[i]] += quantity[i]

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

	def new_transaction(self, sender, recipient, amount):

		"""
		Creates a new transaction to go into the next mined Block
		:param sender: <str> Address of the Sender
		:param recipient: <str> Address of the Recipient
		:param amount: <int> Amount
		:return: <int> The index of the Block that will hold this transaction
		"""
		if self.valid_transaction(sender,recipient,amount):

			a_transaction = {
				'sender' : sender,
				'recipient': recipient,
				'amount' : amount,
			}

			if sender=="0":
				self.none_used_transactions.append(a_transaction)
				self.current_transactions.append(a_transaction)
				return self.last_block['index']+1

			else:
				amount_used ,new_none_used_transactions= self.update_used_transactions(a_transaction)
				if self.equivalent(amount_used,amount):#amount_used == amount:
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

	def update_used_transactions(self,a_transaction):
		print("start", len(self.none_used_transactions))
		amount_used = dict()
		sender = a_transaction['sender']
		recipient = a_transaction['recipient']
		amount_needed = a_transaction['amount']
		new_none_used_transactions = []
		for ing in amount_needed:
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
					new_transaction = {'sender':sender,'recipient':sender,'amount':amount_left}
					new_none_used_transactions.append(new_transaction)
			else:
				new_none_used_transactions.append(transaction)
		return amount_used, new_none_used_transactions
	

	def equivalent(self,a1,a2):
		for i in a1:
			if a1[i]!=a2[i]:
				return False
		return True


	def valid_transaction(self, sender, recipient,amount):
		actor = dict()
		if recipient in self.labs:
			actor = self.labs
		elif recipient in self.suppliers:
			actor = self.suppliers
		elif recipient in self.pharmas:
			actor = self.pharmas

		#validate that the actor is allowed to recieve this
		'''
		for a in amount:
			if recipient in actor:
				if a not in actor[recipient]["allowed"]:
					return False
		'''
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
lab_key1 = 1234
vacinesl1 = ["vacine_1"]
products_allowedl1 = ["ing1","ing2","ing3"]
blockchain.add_lab(lab_key1,vacinesl1,products_allowedl1)
#supplier1
supplier_key1 = 2457
products_alloweds1 = ["ing1","ing2","ing3"]
blockchain.add_suppliers(supplier_key1,products_alloweds1)

#pharma1 
pharma_key1 = 10385
vacinesp1 = ["vacine_1"]
blockchain.add_pharmas(pharma_key1, vacinesp1)




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

	response = {
		'message' : "New Block Forged",
		'index' : block['index'],
		'transactions' : block['transactions'],
		'proof' : block['proof'],
		'previous_hash': block['previous_hash'],
	}
	

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

if __name__ == '__main__':
	app.run(host='0.0.0.0', port=5000) #runs the server on port 5000

