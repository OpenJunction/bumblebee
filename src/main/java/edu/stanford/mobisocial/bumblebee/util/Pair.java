package edu.stanford.mobisocial.bumblebee.util;

public class Pair<L,R> {

    public final R right;
    public final L left;

    public Pair(L left, R right) {
        this.left = left;
        this.right = right;
    }

    public int hashCode() { return left.hashCode() ^ right.hashCode(); }

    public boolean equals(Object o) {
        if (o == null) return false;
        if (!(o instanceof Pair)) return false;
        Pair<?,?> pairo = (Pair<?,?>) o;
        return this.left.equals(pairo.left) &&
            this.right.equals(pairo.right);
    }

}