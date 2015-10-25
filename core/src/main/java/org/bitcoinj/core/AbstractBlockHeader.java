/*
 * Copyright 2011 Google Inc.
 * Copyright 2014 Andreas Schildbach
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.bitcoinj.core;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Preconditions;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.util.Date;
import java.util.EnumSet;
import javax.annotation.Nullable;
import static org.bitcoinj.core.Coin.FIFTY_COINS;
import org.bitcoinj.script.Script;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Common superclass for all block-like messages.
 *
 * @author Ross Nicoll
 */
public abstract class AbstractBlockHeader extends Message {
    /**
     * Flags used to control which elements of block validation are done on
     * received blocks.
     */
    public enum VerifyFlag {
        /** Check that block height is in coinbase transaction (BIP 34). */
        HEIGHT_IN_COINBASE
    }

    protected static final Logger log = LoggerFactory.getLogger(AbstractBlockHeader.class);
    /** How many bytes are required to represent a block header WITHOUT the trailing 00 length byte. */
    public static final int HEADER_SIZE = 80;

    static final long ALLOWED_TIME_DRIFT = 2 * 60 * 60; // Same value as official client.

    /**
     * A constant shared by the entire network: how large in bytes a block is allowed to be. One day we may have to
     * upgrade everyone to change this, so Bitcoin can continue to grow. For now it exists as an anti-DoS measure to
     * avoid somebody creating a titanically huge but valid block and forcing everyone to download/store it forever.
     */
    public static final int MAX_BLOCK_SIZE = 1 * 1000 * 1000;
    /** Value to use if the block height is unknown */
    public static final int BLOCK_HEIGHT_UNKNOWN = -1;
    /** Height of the first block */
    public static final int BLOCK_HEIGHT_GENESIS = 0;

    public static final long BLOCK_VERSION_GENESIS = 1;
    /** Block version introduced in BIP 34: Height in coinbase */
    public static final long BLOCK_VERSION_BIP34 = 2;
    /** Block version introduced in BIP 66: Strict DER signatures */
    public static final long BLOCK_VERSION_BIP66 = 3;

    // It's pretty weak to have this around at runtime: fix later.
    protected static final byte[] pubkeyForTesting = new ECKey().getPubKey();
    // Fields defined as part of the protocol format.
    private long version;
    protected Sha256Hash prevBlockHash;
    protected Sha256Hash merkleRoot;
    protected long time;
    protected long difficultyTarget; // "nBits"
    protected long nonce;
    /** Stores the hash of the block. If null, getHash() will recalculate it. */
    protected Sha256Hash hash;
    protected boolean headerBytesValid;
    // Blocks can be encoded in a way that will use more bytes than is optimal (due to VarInts having multiple encodings)
    // MAX_BLOCK_SIZE must be compared to the optimal encoding, not the actual encoding, so when parsing, we keep track
    // of the size of the ideal encoding in addition to the actual message size (which Message needs)
    protected int optimalEncodingMessageSize;

    protected AbstractBlockHeader(NetworkParameters params) {
        super(params);
    }

    /** Special case constructor, used for the genesis node, cloneAsHeader and unit tests. */
    protected AbstractBlockHeader(NetworkParameters params, long setVersion) {
        super(params);
        // Set up a few basic things. We are not complete after this though.
        version = setVersion;
        difficultyTarget = 0x1d07fff8L;
        time = System.currentTimeMillis() / 1000;
        prevBlockHash = Sha256Hash.ZERO_HASH;

        length = HEADER_SIZE;
    }

    protected AbstractBlockHeader(NetworkParameters params, byte[] payload, int offset, MessageSerializer serializer, int length) {
        super(params, payload, offset, serializer, length);
    }

    /**
     * Construct a block initialized with all the given fields.
     * @param params Which network the block is for.
     * @param version This should usually be set to 1 or 2, depending on if the height is in the coinbase input.
     * @param prevBlockHash Reference to previous block in the chain or {@link Sha256Hash#ZERO_HASH} if genesis.
     * @param merkleRoot The root of the merkle tree formed by the transactions.
     * @param time UNIX time when the block was mined.
     * @param difficultyTarget Number which this block hashes lower than.
     * @param nonce Arbitrary number to make the block hash lower than the target.
     * @param transactions List of transactions including the coinbase.
     */
    protected AbstractBlockHeader(NetworkParameters params, long version, Sha256Hash prevBlockHash, Sha256Hash merkleRoot, long time,
                 long difficultyTarget, long nonce) {
        super(params);
        this.version = version;
        this.prevBlockHash = prevBlockHash;
        this.merkleRoot = merkleRoot;
        this.time = time;
        this.difficultyTarget = difficultyTarget;
        this.nonce = nonce;
    }

    @Override
    protected void parse() throws ProtocolException {
        // header
        cursor = offset;
        version = readUint32();
        prevBlockHash = readHash();
        merkleRoot = readHash();
        time = readUint32();
        difficultyTarget = readUint32();
        nonce = readUint32();
        hash = Sha256Hash.wrapReversed(Sha256Hash.hashTwice(payload, offset, cursor - offset));
        headerBytesValid = serializer.isParseRetainMode();
        length = cursor - offset;
    }

    public int getOptimalEncodingMessageSize() {
        if (optimalEncodingMessageSize != 0) {
            return optimalEncodingMessageSize;
        }
        optimalEncodingMessageSize = bitcoinSerialize().length;
        return optimalEncodingMessageSize;
    }

    // default for testing
    void writeHeader(OutputStream stream) throws IOException {
        // try for cached write first
        if (headerBytesValid && payload != null && payload.length >= offset + HEADER_SIZE) {
            stream.write(payload, offset, HEADER_SIZE);
            return;
        }
        // fall back to manual write
        Utils.uint32ToByteStreamLE(version, stream);
        stream.write(prevBlockHash.getReversedBytes());
        stream.write(getMerkleRoot().getReversedBytes());
        Utils.uint32ToByteStreamLE(time, stream);
        Utils.uint32ToByteStreamLE(difficultyTarget, stream);
        Utils.uint32ToByteStreamLE(nonce, stream);
    }

    /**
     * Special handling to check if we have a valid byte array for both header
     * and transactions
     *
     * @throws IOException
     */
    @Override
    public byte[] bitcoinSerialize() {
        // we have completely cached byte array.
        if (headerBytesValid) {
            Preconditions.checkNotNull(payload, "Bytes should never be null if headerBytesValid");
            if (length == payload.length) {
                return payload;
            } else {
                // byte array is offset so copy out the correct range.
                byte[] buf = new byte[length];
                System.arraycopy(payload, offset, buf, 0, length);
                return buf;
            }
        }
        // At least one of the two cacheable components is invalid
        // so fall back to stream write since we can't be sure of the length.
        ByteArrayOutputStream stream = new UnsafeByteArrayOutputStream(length == UNKNOWN_LENGTH ? HEADER_SIZE : length);
        try {
            writeHeader(stream);
        } catch (IOException e) {
            // Cannot happen, we are serializing to a memory stream.
        }
        return stream.toByteArray();
    }

    @Override
    protected void bitcoinSerializeToStream(OutputStream stream) throws IOException {
        writeHeader(stream);
    }

    protected void unCacheHeader() {
        headerBytesValid = false;
        payload = null;
        hash = null;
    }

    /**
     * Calculates the block hash by serializing the block and hashing the
     * resulting bytes.
     */
    protected Sha256Hash calculateHash() {
        try {
            ByteArrayOutputStream bos = new UnsafeByteArrayOutputStream(HEADER_SIZE);
            writeHeader(bos);
            return Sha256Hash.wrapReversed(Sha256Hash.hashTwice(bos.toByteArray()));
        } catch (IOException e) {
            throw new RuntimeException(e); // Cannot happen.
        }
    }

    /**
     * <p>A utility method that calculates how much new Bitcoin would be created by the block at the given height.
     * The inflation of Bitcoin is predictable and drops roughly every 4 years (210,000 blocks). At the dawn of
     * the system it was 50 coins per block, in late 2012 it went to 25 coins per block, and so on. The size of
     * a coinbase transaction is inflation plus fees.</p>
     *
     * <p>The half-life is controlled by {@link org.bitcoinj.core.NetworkParameters#getSubsidyDecreaseBlockCount()}.
     * </p>
     */
    public Coin getBlockInflation(int height) {
        return FIFTY_COINS.shiftRight(height / params.getSubsidyDecreaseBlockCount());
    }

    /**
     * Returns the hash of the block (which for a valid, solved block should be below the target) in the form seen on
     * the block explorer. If you call this on block 1 in the mainnet chain
     * you will get "00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048".
     */
    public String getHashAsString() {
        return getHash().toString();
    }

    /**
     * Returns the hash of the block (which for a valid, solved block should be
     * below the target). Big endian.
     */
    @Override
    public Sha256Hash getHash() {
        if (hash == null) {
            hash = calculateHash();
        }
        return hash;
    }

    /**
     * The number that is one greater than the largest representable SHA-256
     * hash.
     */
    private static BigInteger LARGEST_HASH = BigInteger.ONE.shiftLeft(256);

    /**
     * Returns the work represented by this block.<p>
     *
     * Work is defined as the number of tries needed to solve a block in the
     * average case. Consider a difficulty target that covers 5% of all possible
     * hash values. Then the work of the block will be 20. As the target gets
     * lower, the amount of work goes up.
     */
    public BigInteger getWork() throws VerificationException {
        BigInteger target = getDifficultyTargetAsInteger();
        return LARGEST_HASH.divide(target.add(BigInteger.ONE));
    }

    /** Returns a copy of the block, but without any transactions. */
    public BlockHeader cloneAsHeader() {
        BlockHeader header = new BlockHeader(params, BLOCK_VERSION_GENESIS);
        copyBitcoinHeaderTo(header);
        return header;
    }

    /** Copy the block without transactions into the provided empty block. */
    protected final void copyBitcoinHeaderTo(final AbstractBlockHeader block) {
        block.nonce = nonce;
        block.prevBlockHash = prevBlockHash;
        block.merkleRoot = getMerkleRoot();
        block.version = version;
        block.time = time;
        block.difficultyTarget = difficultyTarget;
        // block.transactions = null;
        block.hash = getHash();
    }

    /**
     * Returns a multi-line string containing a description of the contents of
     * the block. Use for debugging purposes only.
     */
    @Override
    public String toString() {
        StringBuilder s = toStringBuilder();
        return s.toString();
    }

    protected StringBuilder toStringBuilder() {
        StringBuilder s = new StringBuilder("v");
        s.append(version);
        s.append(" block: \n");
        s.append("   previous block: ").append(getPrevBlockHash()).append("\n");
        s.append("   merkle root: ").append(getMerkleRoot()).append("\n");
        s.append("   time: [").append(time).append("] ").append(Utils.dateTimeFormat(time * 1000)).append("\n");
        s.append("   difficulty target (nBits): ").append(difficultyTarget).append("\n");
        s.append("   nonce: ").append(nonce).append("\n");
        return s;
    }

    /**
     * Returns the difficulty target as a 256 bit value that can be compared to a SHA-256 hash. Inside a block the
     * target is represented using a compact form. If this form decodes to a value that is out of bounds, an exception
     * is thrown.
     */
    public BigInteger getDifficultyTargetAsInteger() throws VerificationException {
        BigInteger target = Utils.decodeCompactBits(difficultyTarget);
        if (target.signum() <= 0 || target.compareTo(params.maxTarget) > 0) {
            throw new VerificationException("Difficulty target is bad: " + target.toString());
        }
        return target;
    }

    /** Returns true if the hash of the block is OK (lower than difficulty target). */
    protected boolean checkProofOfWork(boolean throwException) throws VerificationException {
        // This part is key - it is what proves the block was as difficult to make as it claims
        // to be. Note however that in the context of this function, the block can claim to be
        // as difficult as it wants to be .... if somebody was able to take control of our network
        // connection and fork us onto a different chain, they could send us valid blocks with
        // ridiculously easy difficulty and this function would accept them.
        //
        // To prevent this attack from being possible, elsewhere we check that the difficultyTarget
        // field is of the right value. This requires us to have the preceeding blocks.
        BigInteger target = getDifficultyTargetAsInteger();
        BigInteger h = getHash().toBigInteger();
        if (h.compareTo(target) > 0) {
            // Proof of work check failed!
            if (throwException) {
                throw new VerificationException("Hash is higher than target: " + getHashAsString() + " vs " + target.toString(16));
            } else {
                return false;
            }
        }
        return true;
    }

    protected void checkTimestamp() throws VerificationException {
        // Allow injection of a fake clock to allow unit testing.
        long currentTime = Utils.currentTimeSeconds();
        if (time > currentTime + ALLOWED_TIME_DRIFT) {
            throw new VerificationException(String.format("Block too far in future: %d vs %d", time, currentTime + ALLOWED_TIME_DRIFT));
        }
    }

    /**
     * Checks the block data to ensure it follows the rules laid out in the network parameters. Specifically,
     * throws an exception if the proof of work is invalid, or if the timestamp is too far from what it should be.
     * This is <b>not</b> everything that is required for a block to be valid, only what is checkable independent
     * of the chain and without a transaction index.
     *
     * @throws VerificationException
     */
    public void verifyHeader() throws VerificationException {
        // Prove that this block is OK. It might seem that we can just ignore most of these checks given that the
        // network is also verifying the blocks, but we cannot as it'd open us to a variety of obscure attacks.
        //
        // Firstly we need to ensure this block does in fact represent real work done. If the difficulty is high
        // enough, it's probably been done by the network.
        checkProofOfWork(true);
        checkTimestamp();
    }

    /**
     * Verifies both the header and that the transactions hash to the merkle root.
     *
     * @param height block height, if known, or -1 otherwise.
     * @param flags flags to indicate which tests should be applied (i.e.
     * whether to test for height in the coinbase transaction).
     * @throws VerificationException if there was an error verifying the block.
     */
    public void verify(final int height, final EnumSet<VerifyFlag> flags) throws VerificationException {
        verifyHeader();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        return getHash().equals(((Block) o).getHash());
    }

    @Override
    public int hashCode() {
        return getHash().hashCode();
    }

    /**
     * Returns the merkle root in big endian form.
     */
    public Sha256Hash getMerkleRoot() {
        return merkleRoot;
    }

    /** Exists only for unit testing. */
    void setMerkleRoot(Sha256Hash value) {
        unCacheHeader();
        merkleRoot = value;
        hash = null;
    }

    /** Returns the version of the block data structure as defined by the Bitcoin protocol. */
    public long getVersion() {
        return version;
    }

    /**
     * Returns the hash of the previous block in the chain, as defined by the block header.
     */
    public Sha256Hash getPrevBlockHash() {
        return prevBlockHash;
    }

    void setPrevBlockHash(Sha256Hash prevBlockHash) {
        unCacheHeader();
        this.prevBlockHash = prevBlockHash;
        this.hash = null;
    }

    /**
     * Returns the time at which the block was solved and broadcast, according to the clock of the solving node. This
     * is measured in seconds since the UNIX epoch (midnight Jan 1st 1970).
     */
    public long getTimeSeconds() {
        return time;
    }

    /**
     * Returns the time at which the block was solved and broadcast, according to the clock of the solving node.
     */
    public Date getTime() {
        return new Date(getTimeSeconds() * 1000);
    }

    public void setTime(long time) {
        unCacheHeader();
        this.time = time;
        this.hash = null;
    }

    /**
     * Returns the difficulty of the proof of work that this block should meet encoded <b>in compact form</b>. The {@link
     * BlockChain} verifies that this is not too easy by looking at the length of the chain when the block is added.
     * To find the actual value the hash should be compared against, use
     * {@link org.bitcoinj.core.Block#getDifficultyTargetAsInteger()}. Note that this is <b>not</b> the same as
     * the difficulty value reported by the Bitcoin "getdifficulty" RPC that you may see on various block explorers.
     * That number is the result of applying a formula to the underlying difficulty to normalize the minimum to 1.
     * Calculating the difficulty that way is currently unsupported.
     */
    public long getDifficultyTarget() {
        return difficultyTarget;
    }

    /** Sets the difficulty target in compact form. */
    public void setDifficultyTarget(long compactForm) {
        unCacheHeader();
        this.difficultyTarget = compactForm;
        this.hash = null;
    }

    /**
     * Returns the nonce, an arbitrary value that exists only to make the hash of the block header fall below the
     * difficulty target.
     */
    public long getNonce() {
        return nonce;
    }

    /** Sets the nonce and clears any cached data. */
    public void setNonce(long nonce) {
        unCacheHeader();
        this.nonce = nonce;
        this.hash = null;
    }

    @VisibleForTesting
    boolean isHeaderBytesValid() {
        return headerBytesValid;
    }

    /**
     * Get the number of transactions contained. For a block header this is
     * always 0, but subclasses can override this method.
     */
    public int getTransactionCount() {
        return 0;
    }

    // ///////////////////////////////////////////////////////////////////////////////////////////////
    // Unit testing related methods.

    // Used to make transactions unique.
    protected static int txCounter;

    static final byte[] EMPTY_BYTES = new byte[32];

    /**
     * Returns a solved block that builds on top of this one. This exists for unit tests.
     */
    @VisibleForTesting
    public Block createNextBlock(Address to, long version, long time, int blockHeight) {
        return createNextBlock(to, version, null, time, pubkeyForTesting, FIFTY_COINS, blockHeight);
    }

    /**
     * Returns a solved block that builds on top of this one. This exists for unit tests.
     * In this variant you can specify a public key (pubkey) for use in generating coinbase blocks.
     * 
     * @param height block height, if known, or -1 otherwise.
     */
    Block createNextBlock(@Nullable final Address to, final long version,
                          @Nullable TransactionOutPoint prevOut, final long time,
                          final byte[] pubKey, final Coin coinbaseValue,
                          final int height) {
        Block b = new Block(params, version);
        b.setDifficultyTarget(difficultyTarget);
        b.addCoinbaseTransaction(pubKey, coinbaseValue, height);

        if (to != null) {
            // Add a transaction paying 50 coins to the "to" address.
            Transaction t = new Transaction(params);
            t.addOutput(new TransactionOutput(params, t, FIFTY_COINS, to));
            // The input does not really need to be a valid signature, as long as it has the right general form.
            TransactionInput input;
            if (prevOut == null) {
                input = new TransactionInput(params, t, Script.createInputScript(EMPTY_BYTES, EMPTY_BYTES));
                // Importantly the outpoint hash cannot be zero as that's how we detect a coinbase transaction in isolation
                // but it must be unique to avoid 'different' transactions looking the same.
                byte[] counter = new byte[32];
                counter[0] = (byte) txCounter;
                counter[1] = (byte) (txCounter++ >> 8);
                input.getOutpoint().setHash(Sha256Hash.wrap(counter));
            } else {
                input = new TransactionInput(params, t, Script.createInputScript(EMPTY_BYTES, EMPTY_BYTES), prevOut);
            }
            t.addInput(input);
            b.addTransaction(t);
        }

        b.setPrevBlockHash(getHash());
        // Don't let timestamp go backwards
        if (getTimeSeconds() >= time)
            b.setTime(getTimeSeconds() + 1);
        else
            b.setTime(time);
        b.solve();
        try {
            b.verifyHeader();
        } catch (VerificationException e) {
            throw new RuntimeException(e); // Cannot happen.
        }
        if (b.getVersion() != version) {
            throw new RuntimeException();
        }
        return b;
    }

    @VisibleForTesting
    public Block createNextBlock(@Nullable Address to, TransactionOutPoint prevOut) {
        return createNextBlock(to, BLOCK_VERSION_GENESIS, prevOut, getTimeSeconds() + 5, pubkeyForTesting, FIFTY_COINS, BLOCK_HEIGHT_UNKNOWN);
    }

    @VisibleForTesting
    public Block createNextBlock(@Nullable Address to, Coin value) {
        return createNextBlock(to, BLOCK_VERSION_GENESIS, null, getTimeSeconds() + 5, pubkeyForTesting, value, BLOCK_HEIGHT_UNKNOWN);
    }

    @VisibleForTesting
    public Block createNextBlock(@Nullable Address to) {
        return createNextBlock(to, FIFTY_COINS);
    }

    @VisibleForTesting
    public Block createNextBlockWithCoinbase(long version, byte[] pubKey, Coin coinbaseValue, final int height) {
        return createNextBlock(null, version, (TransactionOutPoint) null,
                               Utils.currentTimeSeconds(), pubKey, coinbaseValue, height);
    }

    /**
     * Create a block sending 50BTC as a coinbase transaction to the public key specified.
     * This method is intended for test use only.
     */
    @VisibleForTesting
    Block createNextBlockWithCoinbase(long version, byte[] pubKey, final int height) {
        return createNextBlock(null, version, (TransactionOutPoint) null,
                               Utils.currentTimeSeconds(), pubKey, FIFTY_COINS, height);
    }
}
