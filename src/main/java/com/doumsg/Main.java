package com.doumsg;

public class Main {
    public static void main(String[] args) {
        EcdhCrypt ecdhCrypt = new EcdhCrypt();
        ecdhCrypt.initShareKey();
        byte[] pub_key = ecdhCrypt._c_pub_key;
        byte[] share_key = ecdhCrypt._g_share_key;
        System.out.println("pub_key = " + HexUtils.bytesToHexString(pub_key));
        System.out.println("share_key = " + HexUtils.bytesToHexString(share_key));

    }
}