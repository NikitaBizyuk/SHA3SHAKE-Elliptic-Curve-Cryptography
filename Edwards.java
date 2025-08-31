import java.awt.*;
import java.math.BigInteger;

import static java.lang.Math.sqrt;

/**
 * Arithmetic on Edwards elliptic curves.
 */
public class Edwards {


    public static final BigInteger p = BigInteger.valueOf(2).
            pow(256).subtract(BigInteger.valueOf(189));
    public static final BigInteger d = BigInteger.valueOf(15343);
    public static final BigInteger r = BigInteger.valueOf(2).
            pow(254).subtract(new BigInteger("87175310462106073678594642380840586067"));
    private Point generator;

    /**
     * Create an instance of the default curve NUMS-256.
     */
    public Edwards() {
        BigInteger y0 = p.subtract(BigInteger.valueOf(4));
        BigInteger y0Squared = y0.multiply(y0).mod(p);
        BigInteger numerator = BigInteger.ONE.subtract(y0Squared).mod(p);
        BigInteger denominator = BigInteger.ONE.subtract(d.multiply(y0Squared)).mod(p);
        BigInteger radicand = numerator.multiply(denominator.modInverse(p)).mod(p);
        BigInteger x0 = sqrt(radicand,p,false);
        if(x0 == null){
            throw new RuntimeException("failed to compute x - coordinate");
         }
        this.generator = new Point(x0,y0);
        if(!isPoint(x0,y0)){
            throw new RuntimeException("Generated point is not on the curve");
        }
    }

    /**
     * Determine if a given affine coordinate pair P = (x, y)
     * defines a point on the curve.
     *
     * @param x x-coordinate of presumed point on the curve
     * @param y y-coordinate of presumed point on the curve
     * @return whether P is really a point on the curve
     */
    public boolean isPoint(BigInteger x, BigInteger y) {
        BigInteger x2 = x.multiply(x).mod(p);
        BigInteger y2 = y.multiply(y).mod(p);
        BigInteger left = x2.add(y2).mod(p);
        BigInteger right = BigInteger.ONE.add(d.multiply(x2).multiply(y2)).mod(p);
        return left.equals(right);
        }

    /**
     * Find a generator G on the curve with the smallest possible
     * y-coordinate in absolute value.
     *
     * @return G.
     */
    public Point gen() {
        return generator;
    }

    /**
     * Create a point from its y-coordinate and
     * the least significant bit (LSB) of its x-coordinate.
     *
     * @param y the y-coordinate of the desired point
     * @param x_lsb the LSB of its x-coordinate
     * @return point (x, y) if it exists and has order r,
     * otherwise the neutral element O = (0, 1)
     */
    public Point getPoint(BigInteger y, boolean x_lsb) {
        BigInteger y2 = y.multiply(y).mod(p);
        BigInteger numerator = BigInteger.ONE.subtract(y2).mod(p);
        BigInteger denominator = BigInteger.ONE.subtract(d.multiply(y2)).mod(p);
        if(denominator.equals(BigInteger.ZERO)){
            return new Point();
        }
        BigInteger denomInv = denominator.modInverse(p);
        BigInteger radicand = numerator.multiply(denomInv).mod(p);
        BigInteger x = sqrt(radicand,p,x_lsb);
        if(x == null || !isPoint(x,y)){
            return new Point();
        }
        Point point = new Point(x,y);
        return point;
    }

    public static BigInteger sqrt(BigInteger v, BigInteger p, boolean lsb){
        assert (p.testBit(0) && p.testBit(1)); // p = 3 (mod 4)
        if (v.signum() == 0) {
            return BigInteger.ZERO;
        }
        BigInteger r = v.modPow(p.shiftRight(2).add(BigInteger.ONE), p);
        if (r.testBit(0) != lsb) {
            r = p.subtract(r); // correct the lsb
        }
        return (r.multiply(r).subtract(v).mod(p).signum() == 0) ? r : null;
    }

    /**
     * Display a human-readable representation of this curve.
     *
     * @return a string of form "E: x^2 + y^2 = 1 + d*x^2*y^2 mod p"
     * where E is a suitable curve name (e.g. NUMS ed-256-mers*),
     * d is the actual curve equation coefficient defining this curve,
     * and p is the order of the underlying finite field F_p.
     */
    public String toString() {
        return "NUMS ed-256-mers*: x^2 + y^2 = 1 + " + d + "*x^2*y^2 mod " + p;
    }

    /**
     * Edwards curve point in affine coordinates.
     * NB: this is a nested class, enclosed within the Edwards class.
     */
    public class Point {

        private BigInteger x;
        private BigInteger y;

        /**
         * Create a copy of the neutral element on this curve.
         */
        public Point() {
            this.x = BigInteger.ZERO;
            this.y = BigInteger.ONE;
        }

        /**
         * Create a point from its coordinates (assuming
         * these coordinates really define a point on the curve).
         *
         * @param x the x-coordinate of the desired point
         * @param y the y-coordinate of the desired point
         */
        private Point(BigInteger x, BigInteger y) {
            this.x = x.mod(p);
            this.y = y.mod(p);
        }

        /**
         * Determine if this point is the neutral element O on the curve.
         *
         * @return true iff this point is O
         */
        public boolean isZero() {
            return x.equals(BigInteger.ZERO) && y.equals(BigInteger.ONE);
        }

        /**
         * Determine if a given point P stands for
         * the same point on the curve as this.
         *
         * @param P a point (presumably on the same curve as this)
         * @return true iff P stands for the same point as this
         */
        public boolean equals(Point P) {
            return this.x.equals(P.x) && this.y.equals(P.y);
        }

        /**
         * Given a point P = (x, y) on the curve,
         * return its opposite -P = (-x, y).
         *
         * @return -P
         */
        public Point negate() {
            return new Point(p.subtract(x),y);
        }

        /**
         * Add two given points on the curve, this and P.
         *
         * @param P a point on the curve
         * @return this + P
         */
        public Point add(Point P) {
            BigInteger x1 = this.x;
            BigInteger y1 = this.y;
            BigInteger x2 = P.x;
            BigInteger y2 = P.y;

            BigInteger x1y2 = x1.multiply(y2).mod(p);
            BigInteger y1x2 = y1.multiply(x2).mod(p);
            BigInteger y1y2 = y1.multiply(y2).mod(p);
            BigInteger x1x2 = x1.multiply(x2).mod(p);
            BigInteger dx1x2y1y2 = d.multiply(x1x2).multiply(y1y2).mod(p);

            BigInteger x3_num = x1y2.add(y1x2).mod(p);
            BigInteger x3_den = BigInteger.ONE.add(dx1x2y1y2).mod(p);
            BigInteger y3_num = y1y2.subtract(x1x2).mod(p);
            BigInteger y3_den = BigInteger.ONE.subtract(dx1x2y1y2).mod(p);

            BigInteger x3 = x3_num.multiply(x3_den.modInverse(p)).mod(p);
            BigInteger y3 = y3_num.multiply(y3_den.modInverse(p)).mod(p);
            return new Point(x3,y3);
        }

        /**
         * Multiply a point P = (x, y) on the curve by a scalar m.
         *
         * @param m a scalar factor (an integer mod the curve order)
         * @return m*P
         */
        public Point mul(BigInteger m) {
            if(m.equals(BigInteger.ZERO)){
                return new Point();
            }
            m = m.mod(r);
            Point V = new Point();
            Point P = new Point(this.x,this.y);
            int bitLength = m.bitLength();
            for(int i = bitLength - 1; i >= 0; i --){
                V = V.add(V);
                if(m.testBit(i)){
                    V = V.add(P);
                }
            }
            return V;
        }

        /**
         * Display a human-readable representation of this point.
         *
         * @return a string of form "(x, y)" where x and y are
         * the coordinates of this point
         */
        public String toString() {
            return "( " + x + ", " + y + " )";
        }
    }
}
