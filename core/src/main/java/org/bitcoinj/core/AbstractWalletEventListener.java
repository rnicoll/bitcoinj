/**
 * Copyright 2011 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.bitcoinj.core;

import org.bitcoinj.script.Script;
import org.bitcoinj.wallet.AbstractKeyChainEventListener;

import java.util.List;

/**
 * Convenience implementation of {@link WalletEventListener}.
 */
public abstract class AbstractWalletEventListener<T extends Block> extends AbstractKeyChainEventListener implements WalletEventListener<T> {
    @Override
    public void onCoinsReceived(Wallet<T> wallet, Transaction<T> tx, Coin prevBalance, Coin newBalance) {
        onChange();
    }

    @Override
    public void onCoinsSent(Wallet<T> wallet, Transaction<T> tx, Coin prevBalance, Coin newBalance) {
        onChange();
    }

    @Override
    public void onReorganize(Wallet<T> wallet) {
        onChange();
    }

    @Override
    public void onTransactionConfidenceChanged(Wallet<T> wallet, Transaction<T> tx) {
        onChange();
    }

    @Override
    public void onKeysAdded(List<ECKey> keys) {
        onChange();
    }

    @Override
    public void onScriptsChanged(Wallet<T> wallet, List<Script> scripts, boolean isAddingScripts) {
        onChange();
    }

    @Override
    public void onWalletChanged(Wallet<T> wallet) {
        onChange();
    }

    public void onChange() {
    }
}
