/*
 * Copyright 2015 jrn.
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

/**
 *
 * @author jrn
 */
public class BlockHeader extends AbstractBlockHeader {

    public BlockHeader(NetworkParameters params, long version) {
        super(params, version);
    }

    public BlockHeader(NetworkParameters params,  byte[] payloadBytes, int offset, MessageSerializer serializer, int length) {
        super(params, payloadBytes, offset, serializer, length);
    }

    public BlockHeader(NetworkParameters params, long version, Sha256Hash prevBlockHash, Sha256Hash merkleRoot, long time, long difficultyTarget, long nonce) {
        super(params, version, prevBlockHash, merkleRoot, time, difficultyTarget, nonce);
    }

    /** Returns a copy of the block, but without any transactions. */
    @Override
    public BlockHeader cloneAsHeader() {
        return this;
    }

    @Override
    protected void parse() throws ProtocolException {
        super.parse();
        optimalEncodingMessageSize = HEADER_SIZE;
    }
}
