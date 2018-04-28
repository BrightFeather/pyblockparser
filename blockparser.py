import os
import plyvel
import struct
from datetime import datetime
import hashlib


#  read a single block from the block chain into memory
#  Here is how a block is read.

# Step #1 : We read the block format version
# Step #2 : We read the hash of the previous block
# Step #3 : We read the merkle root hash
# Step #4 : We read the block time stamp
# Step #5 : We read a 'bits' field; internal use defined by the bitcoin software
# Step #6 : We read the 'nonce' value; a randum number generated during the mining process.
# Step #7 : We read the transaction count
# Step #8 : For/Each Transaction
#           : (a) We read the transaction version number.
#           : (b) We read the number of inputs.
# Step #8a : For/Each input
# 			: (a) Read the hash of the input transaction
# 			: (b) Read the input transaction index
# 			: (c) Read the response script length
# 			: (d) Read the response script data; parsed using the bitcoin scripting system; a little virtual machine.
# Step #8aa	: (a) Read the sequence number.
# 			: (b) Read the number of outputs
# Step #8b : For/Each Output
# 			: (a) Read the value of the output in BTC fixed decimal; see docs.
# 			: (b) Read the length of the challenge script.
# 			: (c) Read the challenge script
# Step #9 Read the LockTime; a value currently always hard-coded to zero

# Refer symbols like B1 to http://2.bp.blogspot.com/-DaJcdsyqQSs/UsiTXNHP-0I/AAAAAAAATC0/kiFRowh-J18/s1600/blockchain.png.


# Part 1 read .dat file
# repo = '/Users/chenweijia/Documents/Cornell/Courses/Cryptocurrency/project/bitcoin_parser/bitcoin_parser'

MAGIC_ID = '\xf9\xbe\xb4\xd9'

db_path = './utxo_db'

db = plyvel.DB(db_path, create_if_missing=True)

# processed_blocks_db = plyvel.DB('./processed_blocks', create_if_missing=True)
#
# waiting_blocks_db = plyvel.DB('./waiting_blocks', create_if_missing=True)

class Block(object):
    def __init__(self,header=None,transactions=None):
        self.header = header # instance of Blockheader class
        self.transactions = transactions # instance of Transaction class
        self.num_txn = None
        self.blocksize = None
        # self.num_tx = len(self.transactions)

    def processBlock(self,data,pos):

        header = BlockHeader()
        endIndex, pos = header.processBlockHeader(data, pos)

        txn_in_block = []

        # B9 varianble length integer
        num_tx, pos = varint(data, pos)
        # print "Number of transactions: %d" % num_tx

        txn_start_index = pos
        # go into transactions
        for i in range(num_tx):

            txn = Transaction()

            pos = txn.processTransaction(data,pos)

            txn_in_block.append(txn)

        assert endIndex == pos, "Wrong index at the end of the counter! Ending index should be %d, but got %d instead." \
                                % (endIndex, pos)

        self.header = header
        self.transactions = txn_in_block
        self.num_txn = len(self.transactions)
        self.blocksize = header.header_length

        return pos


class BlockHeader(object):
    def __init__(self,magic_id=None,header_length=None, version_number=None,prev_hash_raw=None,merkle_hash_raw=None,timestamp=None,bits=None,nonce=None):
        self.magic_id = magic_id
        self.header_length = header_length
        self.version_number = version_number
        self.prev_hash_raw = prev_hash_raw
        self.prev_hash = None
        self.merkle_hash_raw = merkle_hash_raw
        self.merkle_hash = None
        self.timestamp = timestamp
        self.bits = bits
        self.nonce = nonce
        self.hashcash = None

    def calculateHashcash(self):

        header_bin = struct.pack(
            '<I32s32sIII',
            self.version_number,
            self.prev_hash_raw,
            self.merkle_hash_raw,
            self.timestamp,
            self.bits,
            self.nonce,
        )
        # The named constructors are much faster than new()
        # and should be preferred.
        h = hashlib.sha256(
            hashlib.sha256(header_bin).digest()
        ).digest()

        self.hashcash = h[::-1].encode('hex')

        return self.hashcash

    def processBlockHeader(self,data,pos):
        # B1 magic id, need to convert from little endian to big endian
        magic_id = data[pos:pos + 4]
        # print magic_id
        assert MAGIC_ID == magic_id, "A magic_id mismatch found at position %d! Found: %s" % (pos, magic_id)
        pos += 4

        # B2 read block size -- length of block = headerlength + 8(B1+B2)
        header_length = struct.unpack_from('<I', data, offset=pos)[0]
        pos += struct.calcsize('<I')

        endIndex = header_length + pos  # for checking index at the end of each block

        # B3-7
        # unsigned int32 version - 4 bytes
        # 32 bytes of previous hash
        # 32 bytes of merkle hash
        # unsigned int32 time - 4 bytes
        # unsigned int32 bits - 4 bytes
        # unsigned int32 nonce - 4 bytes

        version_number, prev_hash_raw, merkle_hash_raw, timestamp, bits, nonce = struct.unpack_from('<I32s32sIII', data,
                                                                                            offset=pos)

        pos += struct.calcsize('<I32s32sIII')

        self.magic_id, self.header_length, self.version_number, self.prev_hash_raw, self.merkle_hash_raw, self.timestamp, self.bits, self.nonce\
            = magic_id, header_length, version_number, prev_hash_raw, merkle_hash_raw, timestamp, bits, nonce

        # compute hash from raw
        self.merkle_hash = self.merkle_hash_raw[::-1].encode('hex')

        self.prev_hash = self.prev_hash_raw[::-1].encode('hex')

        self.calculateHashcash()

        return endIndex, pos

class Transaction(object):
    def __init__(self,input_txn=None, output_txn=None):
        # self.num_tx = num_tx
        self.input_txn = input_txn
        self.output_txn = output_txn
        self.num_input = None
        self.num_output = None
        self.version_number = None
        self.lock_time = None
        self.txn_hash = None
        self.txn_fee = 0

    def processTransaction(self,data,pos):

        txn_start_index = pos

        input_txn, output_txn = [], []

        # T1 transaction version number
        self.version_number = struct.unpack_from('<I', data, offset=pos)[0]
        pos += struct.calcsize('<I')

        # T2 varianble length integer
        num_input, pos = varint(data, pos)

        # print "Number of input transactions in transaction No. %d: %d" % (num_tx, num_input)

        for j in range(num_input):
            txn = InputTransaction()
            pos = txn.processInputTransactions(data, pos)
            input_txn.append(txn)

        # T3 varianble length integer
        num_output, pos = varint(data, pos)

        # print "Number of output transactions in transaction No. %d: %d" % (num_tx, num_output)

        output_starts, output_ends = [], []
        for k in range(num_output):
            tx = OutputTransaction()
            output_starts.append(pos)
            pos = tx.processOutputTransactions(data, pos)
            output_ends.append(pos)
            output_txn.append(tx)



        # T4 transaction lock time
        self.lock_time = struct.unpack_from('<I', data, offset=pos)[0]
        pos += struct.calcsize('<I')

        self.input_txn, self.output_txn  = input_txn, output_txn
        # self.calculateTransactionFee()
        self.num_input = num_input
        self.num_output = num_output

        self.txn_hash = hashlib.sha256(hashlib.sha256(data[txn_start_index:pos]).digest()).digest()[::-1].encode('hex')

        # put every output transaction in this transaction into the leveldb database
        # key: string(transaction + output_txn index), value: bytearray(output_txn hash + output_txn value)
        for i in range(num_output):
            db.put(self.txn_hash + str(i), data[output_starts[i]:output_ends[i]])

        return pos


class InputTransaction(object):
    def __init__(self,prev_hash=None, tx_index=None, script_sig=None, seq_no=None):
        self.prev_hash = prev_hash
        self.tx_index = tx_index
        self.script_sig = script_sig
        self.seq_no = seq_no
        self.is_coinbase = False

    def processInputTransactions(self,data, pos):
        # I1 transaction hash
        prev_hash = struct.unpack_from('<32s', data, offset=pos)[0]
        pos += struct.calcsize('<32s')

        # I2 transaction index
        tx_index = struct.unpack_from('<I', data, offset=pos)[0]
        pos += struct.calcsize('<I')

        # I3 varianble length integer
        script_length, pos = varint(data, pos)

        # I4 input script
        script_sig_seq_no_fmt = '<{}sI'.format(script_length)
        script_sig, seq_no = struct.unpack_from(
            script_sig_seq_no_fmt,
            data,
            offset=pos
        )
        pos += struct.calcsize(script_sig_seq_no_fmt)

        if tx_index == 0xffffffff: # new coin mined, will not take into consideration to transaction fees
            self.is_coinbase = True

        self.prev_hash, self.tx_index, self.script_sig, self.seq_no  = prev_hash, tx_index, script_sig, seq_no

        self.prev_hash = self.prev_hash[::-1].encode('hex')
        return pos

class OutputTransaction(object):
    def __init__(self, value=None, public_key=None ):
        self.value = value
        self.public_key = public_key

    def processOutputTransactions(self, data, pos):
        # O1 value
        value, = struct.unpack_from('<q', data, offset=pos)
        pos += struct.calcsize('<q')

        # O2 variable length integer
        public_key_length, pos = varint(data, pos=pos)

        # O3 public key
        public_key_fmt = '<{}s'.format(public_key_length)
        public_key, = struct.unpack_from(public_key_fmt, data, offset=pos)
        pos += struct.calcsize(public_key_fmt)

        self.value, self.public_key = value, public_key
        # print self.public_key.encode('hex'), self.value

        # hash public key
        # hashlib.sha256(self.public_key.encode('hex'))

        return pos


class Parser(object):
    def __init__(self,db_path=None):
        pass
        # if db_path == None:
        #     db_path = './utxo_db'

        # self.db = plyvel.DB(db_path,create_if_missing=True)

    def __del__(self):
        pass
        # self.db.close()


    def parser_repo(self,repo):

        dat_list = []
        for i in os.listdir(repo):
            if i.endswith('.dat') and i.startswith('blk'):
                dat_list.append(i)

        # if no .dat file found
        if dat_list == []:
            print 'No .dat file found!'
            return
        dat_list = sorted(dat_list)
        print dat_list
        for file in dat_list:
            f = open(repo+file,'r')
            self.parse_file(f)

    def parse_file(self,f):
        # f = open(file,'r')
        cur_date = 0

        data = f.read()

        pos = 0 # current position

        blocks_in_one_day = []

        block_counter = 0

        while(1):
            # if block_counter % 10000 == 1:
            print "Processing block #%d in file..." % (block_counter, )
            block = Block()
            pos = block.processBlock(data,pos)

            if block: # block processed
                block_counter += 1

                # TODO edit datetime.datetime.fromtimestamp
                block_date = datetime.fromtimestamp(block.header.timestamp).date()
                # print block_date

                if cur_date == 0: # first block
                    cur_date = block_date
                    blocks_in_one_day.append(block)

                elif cur_date == block_date: # blocks in the same day
                    blocks_in_one_day.append(block)

                else: # blocks in a new day

                    # write down previous blocks to csv file
                    file = open('./blocks/Blocks_'+str(cur_date)+'.csv','w')
                    self.writeHeader(file)
                    for i in xrange(len(blocks_in_one_day)):
                        self.writeBlock(file,blocks_in_one_day[i],block_counter+i)
                    file.close()

                    # print "Blocks in "+str(cur_date)+" processed."

                    # start collecting new blocks
                    cur_date = block_date
                    blocks_in_one_day = [block]

                # in case there are useless symbols between two blocks, as mentioned in http://codesuppository.blogspot.com/2014/01/how-to-parse-bitcoin-blockchain.html
                while struct.unpack_from('<B', data, offset=pos)[0] != 0xf9 and pos<len(data):
                    # print struct.unpack_from('<B', data, offset=pos)
                    pos += 1

                if pos == len(data):
                    print '%d files processed in in file %s.' %(str(block_counter+1), file)
                    return
            else:
                if pos == len(data): # end of the file
                    print '%d files processed in in file %s.' % (str(block_counter + 1), file)
                    return

    def writeHeader(self,file):
        file.write("Date, Block Height, Block Hash, Transaction size, Tranaction No., Number of inputs, \
        Number of outputs, Input hash, Input Value, Output hash, Output Value, Transaction Fee\n")


    def writeBlock(self,file, block,block_counter):
        num_txn = len(block.transactions)

        # TODO: 1. block height 2.
        # Date, block hash, block height, number of transactions in this block
        file.write("%s, %d, %s, %d,"%
                   (datetime.fromtimestamp(block.header.timestamp).date(),block_counter, block.header.hashcash, num_txn))

        for i in xrange(num_txn): # every single transaction
            if i != 0:
                file.write(",,,,")
            txn_fee = 0

            # transaction number, number of inputs, number of outputs
            file.write("%d,  %d, %d," %
                       (i+1, block.transactions[i].num_input, block.transactions[i].num_output))

            # continue to write the first transaction on the same line
            if block.transactions[i].num_input > 0:

                if block.transactions[i].input_txn[0].is_coinbase: # input transaction from coinbase, no need to write
                    file.write(',,')

                else:# input transaction from unspent output, write down
                    txn_hash = block.transactions[i].input_txn[0].prev_hash
                    index = block.transactions[i].input_txn[0].tx_index
                    key = txn_hash+str(index)
                    prev_output_raw = db.get(key)
                    if not prev_output_raw:
                        print "Ah, input transaction not found in database! Block hash: %s" % block.header.hashcash
                        file.write(",,")
                    else:
                        prev_output = OutputTransaction()
                        prev_output.processOutputTransactions(prev_output_raw,0)
                        txn_fee += prev_output.value
                        file.write("%s, %.2f," % (prev_output.public_key.encode("hex"), prev_output.value))

            if block.transactions[i].num_output > 0:
                if txn_fee != -1:
                    # print txn_fee
                    txn_fee -= block.transactions[i].output_txn[0].value
                    # print txn_fee

                file.write("%s, %.2f," % (block.transactions[i].output_txn[0].public_key.encode('hex'),
                                         block.transactions[i].output_txn[0].value))
                file.write("\n")

            count = max(block.transactions[i].num_input, block.transactions[i].num_output)

            # write other parts in new lines
            for j in xrange(1,count):
                file.write(",,,,,,,")
                # input hash, input value
                if j<block.transactions[i].num_input:
                    txn_hash = block.transactions[i].input_txn[j].prev_hash
                    index = block.transactions[i].input_txn[j].tx_index
                    key = txn_hash + str(index)
                    prev_output_raw = db.get(key)
                    if not prev_output_raw:
                        print "Ah, input transaction not found in database!"
                        file.write(",,")
                    else:
                        prev_output = OutputTransaction()
                        prev_output.processOutputTransactions(prev_output_raw,0)
                        txn_fee += prev_output.value
                        file.write("%s, %.2f," % (prev_output.public_key.encode("hex"), prev_output.value))
                else:
                    file.write(",,")

                # output hash, output value
                if j<block.transactions[i].num_output:
                    txn_fee -= block.transactions[i].output_txn[j].value
                    file.write("%s, %.2f," % (block.transactions[i].output_txn[j].public_key.encode('hex'),
                                             block.transactions[i].output_txn[j].value))
                else:
                    file.write(",,")

                # write down transaction fee
                if j == count-1 and txn_fee != -1:
                    file.write("%.2f"%txn_fee)

                file.write("\n")



def varint(data, pos):
    # modified based on: https://github.com/toidi/pyblockchain/blob/master/blockchain/block.py#L16

    """The raw transaction format and several peer-to-peer network messages use
    a type of variable-length integer to indicate the number of bytes in a
    following piece of data.

    Reference:
    https://bitcoin.org/en/developer-reference#compactsize-unsigned-integers

    """
    # variable length integer
    # 1 byte unsigned int8
    value, = struct.unpack_from('<B', data,offset=pos)
    pos += struct.calcsize('<B')

    if value < 0xfd:
        pass
    elif value == 0xfd:
        # 0xfd followed by the number as uint16_t
        value, = struct.unpack_from('<H', data, offset=pos)
        pos += struct.calcsize('<H')
    elif value == 0xfe:
        # 0xfe followed by the number as uint32_t
        value, = struct.unpack_from('<I', data, offset=pos)
        pos += struct.calcsize('<I')
    elif value == 255:
        # 0xff followed by the number as uint64_t
        value, = struct.unpack_from('<Q', data, offset=pos)
        pos += struct.calcsize('<Q')
    return value, pos


# def calculateTransactionFee(transaction):
#
#     input_value = 0
#     output_value = 0
#     if transaction.input_txn is None: # might be from coinbase,
#         print "Error! No input transactions found!"
#         return
#
#     for txn in transaction.input_txn:
#         if txn.is_coinbase: # input from coinbase
#             return -1
#         else: # input from unspend transaction
#
#             # look up transaction in leveldb
#             found = db.get(txn.prev_hash + str(txn.tx_index))
#
#             if not found:
#                 print "Hash not found for current input!"
#                 return None
#                 # break
#             else:
#                 prev_txn = Transaction()
#                 prev_txn.processTransaction(db.get(txn.prev_hash))
#                 value = prev_txn.output_txn[txn.tx_index].value
#
#             input_value += value
#
#     for txn in transaction.output_txn:
#         output_value += txn.value
#     txn_fee = input_value - output_value
#
#     return txn_fee
if __name__ == '__main__':
    from sys import argv

    if len(argv) > 2:
        print "Too many args! Please only give the directory root!"
    else:
        repo = argv[1]
        if not argv[1].endswith('/'):
            repo +='/'
        p = Parser()
        p.parser_repo(repo)