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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * <p>A block header is the metadata around a set of transactions, excluding
 * the transactions themselves.</p>
 */
public class BlockHeader extends Message {
    protected static final Logger log = LoggerFactory.getLogger(BlockHeader.class);
    /** How many bytes are required to represent a block header WITHOUT the trailing 00 length byte. */
    public static final int HEADER_SIZE = 80;
    static final long ALLOWED_TIME_DRIFT = 2 * 60 * 60; // Same value as official client.
    /**
     * The number that is one greater than the largest representable SHA-256
     * hash.
     */
    protected static BigInteger LARGEST_HASH = BigInteger.ONE.shiftLeft(256);
    // Fields defined as part of the protocol format.
    private long version;
    private Sha256Hash prevBlockHash;
    private Sha256Hash merkleRoot;
    private long time;
    private long difficultyTarget; // "nBits"
    private long nonce;
    /** Stores the hash of the block. If null, getHash() will recalculate it. */
    private Sha256Hash hash;
    boolean headerBytesValid;

    protected BlockHeader(NetworkParameters params) {
        super(params);
    }

    /** Special case constructor, used for the genesis node, cloneAsHeader and unit tests. */
    BlockHeader(NetworkParameters params, long setVersion) {
        super(params);
        // Set up a few basic things. We are not complete after this though.
        version = setVersion;
        difficultyTarget = 0x1d07fff8L;
        time = System.currentTimeMillis() / 1000;
        prevBlockHash = Sha256Hash.ZERO_HASH;

        length = HEADER_SIZE;
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
     */
    public BlockHeader(NetworkParameters params, long version, Sha256Hash prevBlockHash, Sha256Hash merkleRoot, long time,
                 long difficultyTarget, long nonce) {
        super(params);
        this.version = version;
        this.prevBlockHash = prevBlockHash;
        this.merkleRoot = merkleRoot;
        this.time = time;
        this.difficultyTarget = difficultyTarget;
        this.nonce = nonce;
    }

    BlockHeader(NetworkParameters params, byte[] payload, int offset, MessageSerializer serializer, int length) {
        super(params, payload, offset, serializer, length);
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
        length = cursor = offset;
    }

    public int getOptimalEncodingMessageSize() {
        return HEADER_SIZE;
    }

    /**
     * Special handling to check if we have a valid byte array.
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
            bitcoinSerializeToStream(stream);
        } catch (IOException e) {
            // Cannot happen, we are serializing to a memory stream.
        }
        return stream.toByteArray();
    }

    @Override
    protected void bitcoinSerializeToStream(OutputStream stream) throws IOException {
        bitcoinSerializeToStream(stream, null);
    }

    /**
     * Serialize the block header to a stream, with a block provided from which
     * to take the merkle root if the current one is invalid.
     * 
     * @param block block to take merkle root from if needed.
     */
    protected void bitcoinSerializeToStream(OutputStream stream, Block block) throws IOException {
        // try for cached write first
        if (headerBytesValid && payload != null && payload.length >= offset + HEADER_SIZE) {
            stream.write(payload, offset, HEADER_SIZE);
            return;
        }
        // fall back to manual write
        Utils.uint32ToByteStreamLE(version, stream);
        stream.write(prevBlockHash.getReversedBytes());
        stream.write(getMerkleRoot(block).getReversedBytes());
        Utils.uint32ToByteStreamLE(time, stream);
        Utils.uint32ToByteStreamLE(difficultyTarget, stream);
        Utils.uint32ToByteStreamLE(nonce, stream);
    }

    protected void unCacheHeader() {
        headerBytesValid = false;
        hash = null;
    }

    /**
     * Calculates the block hash by serializing the block and hashing the
     * resulting bytes.
     */
    protected Sha256Hash calculateHash() {
        try {
            ByteArrayOutputStream bos = new UnsafeByteArrayOutputStream(HEADER_SIZE);
            bitcoinSerializeToStream(bos);
            return Sha256Hash.wrapReversed(Sha256Hash.hashTwice(bos.toByteArray()));
        } catch (IOException e) {
            throw new RuntimeException(e); // Cannot happen.
        }
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
        return hash;
    }

    /**
     * Returns the hash of the block (which for a valid, solved block should be
     * below the target). Big endian.
     * 
     * @param block from which to take transactions if the hash requires to be
     * recalculated.
     */
    protected Sha256Hash getHash(final Block block) {
        if (hash == null) {
            // Ensure the header has a merkle tree
            if (null == merkleRoot) {
                merkleRoot = block.calculateMerkleRoot();
            }

            hash = calculateHash();
        }
        return hash;
    }

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
        return this;
    }

    /** Copy the block without transactions into the provided empty block. */
    protected final void copyBitcoinHeaderTo(final BlockHeader block) {
        block.nonce = nonce;
        block.prevBlockHash = prevBlockHash;
        block.merkleRoot = getMerkleRoot();
        block.version = version;
        block.time = time;
        block.difficultyTarget = difficultyTarget;
        block.hash = getHash();
    }

    /**
     * Returns a multi-line string containing a description of the contents of
     * the block. Use for debugging purposes only.
     */
    @Override
    public String toString() {
        return toStringBuilder().toString();
    }

    /**
     * Internal method for writing the header details to a string builder, which
     * can then either be directly converted to a string for the header, or
     * appended further if part of a full block.
     */
    protected final StringBuilder toStringBuilder() {
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
     * <p>Finds a value of nonce that makes the blocks hash lower than the difficulty target. This is called mining, but
     * solve() is far too slow to do real mining with. It exists only for unit testing purposes.
     *
     * <p>This can loop forever if a solution cannot be found solely by incrementing nonce. It doesn't change
     * extraNonce.</p>
     */
    public void solve(final Block block) {
        while (true) {
            try {
                // Is our proof of work valid yet?
                if (checkProofOfWork(false, block)) {
                    return;
                }
                // No, so increment the nonce and try again.
                setNonce(getNonce() + 1);
            } catch (VerificationException e) {
                throw new RuntimeException(e); // Cannot happen.
            }
        }
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
    protected boolean checkProofOfWork(boolean throwException, Block block)
                                       throws VerificationException {
        // This part is key - it is what proves the block was as difficult to make as it claims
        // to be. Note however that in the context of this function, the block can claim to be
        // as difficult as it wants to be .... if somebody was able to take control of our network
        // connection and fork us onto a different chain, they could send us valid blocks with
        // ridiculously easy difficulty and this function would accept them.
        //
        // To prevent this attack from being possible, elsewhere we check that the difficultyTarget
        // field is of the right value. This requires us to have the preceeding blocks.
        BigInteger target = getDifficultyTargetAsInteger();
        BigInteger h = getHash(block).toBigInteger();
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
    public void verifyHeader(Block block) throws VerificationException {
        // Prove that this block is OK. It might seem that we can just ignore most of these checks given that the
        // network is also verifying the blocks, but we cannot as it'd open us to a variety of obscure attacks.
        //
        // Firstly we need to ensure this block does in fact represent real work done. If the difficulty is high
        // enough, it's probably been done by the network.
        checkProofOfWork(true, block);
        checkTimestamp();
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
     * Returns the merkle root in big endian form. As the header does not
     * contain the transactions, where no merkle root is available, this returns
     * null.
     */
    public Sha256Hash getMerkleRoot() {
        return merkleRoot;
    }

    /**
     * Returns the merkle root in big endian form, calculating it from transactions if necessary.
     */
    public Sha256Hash getMerkleRoot(final Block block) {
        if (null != merkleRoot
            || null == block) {
            return merkleRoot;
        }
        this.merkleRoot = block.calculateMerkleRoot();
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

    protected void clearHash() {
        this.hash = null;
    }
    
}
