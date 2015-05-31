package org.bitcoinj.wallet;

import org.bitcoinj.core.Coin;
import org.bitcoinj.core.TransactionOutput;

import java.util.Collection;
import org.bitcoinj.core.Block;

/**
 * Represents the results of a
 * {@link CoinSelector#select(Coin, java.util.List)} operation. A
 * coin selection represents a list of spendable transaction outputs that sum together to give valueGathered.
 * Different coin selections could be produced by different coin selectors from the same input set, according
 * to their varying policies.
 */
public class CoinSelection<T extends Block> {
    public Coin valueGathered;
    public Collection<TransactionOutput<T>> gathered;

    public CoinSelection(Coin valueGathered, Collection<TransactionOutput<T>> gathered) {
        this.valueGathered = valueGathered;
        this.gathered = gathered;
    }
}
