import org.w3c.dom.DOMException;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import javax.net.ssl.CertPathTrustManagerParameters;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import javax.xml.crypto.*;
import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.sql.*;
import java.sql.Date;
import java.util.*;
import java.io.*;

public class main {

    static String url = "jdbc:postgresql://localhost:5433/test";
    static String user = "postgres";
    static String BDpassword = "admin";
    static KeyStore ks;
    static PublicKey pk;
    static char[] password = null;
    static Scanner sc = new Scanner(System.in);
    static java.sql.Date ed, vd;
    static KeyStore ks1;
    static String p12_u, email;

    public static void main(String[] args) {

        int c = -1;
        while (c != 0) {
            System.out.println("Presione:\n1-> Para guardar un pk12 en la BD\n2-> Para listar los pk12 actuales\n" +
                    "3-> Para exportar un p12 de la BD\n4-> Para firmar un documento\n5-> Para verificar un documneto firmado\n" +
                    "6-> Para validar un p12 por CRL\n7-> Para validar un p12 por OSCP\n0-> Para salir");
            c = Integer.parseInt(sc.nextLine());
            if (c == 1) {
                System.out.println("Introduzca la ruta del p12 a guardar");
                String path_in = sc.nextLine();
                create_keystore(path_in);
                open_p12_file();
                String[] data = new String[6];
                data[0] = email;
                data[1] = p12_u;
                data[4] = e64(pk);
                File p12 = new File(path_in);
                data[5] = es_p12(p12);
                System.out.println("Su p12 ha sido agregado con exito, tiene el numero " + db_flush(data) + " en nuestra BD");
            } else if (c == 2) {
                get_data("select * from test;");
            } else if (c == 3) {
                get_data("select * from test;");
                System.out.println("A nombre de quien esta el p12 que desea exportar?");
                String name = sc.nextLine();
                System.out.println("Donde desea exportarlo?");
                String path_out = sc.nextLine();
                get_data("select * from test where nombre = \'" + name + "\';");
                System.out.println("Exportando...");
                d_p12(get_data("select * from test where nombre = \'" + name + "\';", "p12_file"), name, path_out);
            } else if (c == 4) {
                System.out.println("Introduzca la ruta del archivo q desea firmar");
                String path = sc.nextLine();
                System.out.println("Introduzca la ruta del archivo firmado");
                String output = sc.nextLine();
                sign_XML_document(path, output);
            } else if (c == 5) {
                try {
                    System.out.println("Introduzca la ruta del archivo firmado a comprobar");
                    System.out.println(verify_signature(load_document(sc.nextLine())));
                } catch (Exception e) {
                    e.printStackTrace();
                }
            } else if (c == 6) {
                verify_crl();
            } else if (c == 7) {
                verify_crl();
            }else if (c == 0) {
                break;
            }
        }
    }

    public static String e64(PublicKey pk) {
        return Base64.getEncoder().encodeToString(pk.toString().getBytes(StandardCharsets.UTF_8));
    }

    public static String d64(String coded) {
        return new String(Base64.getDecoder().decode(coded));
    }

    public static String es_p12(File file) {
        String encoded = null;
        try {
            FileInputStream fin = new FileInputStream(file);
            byte[] b = new byte[(int) file.length()];
            fin.read(b);
            encoded = Base64.getEncoder().encodeToString(b);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return encoded;
    }

    public static void d_p12(String cf, String name, String path) {
        try (FileOutputStream fos = new FileOutputStream(path + "exported_" + name + "_p12.p12")) {
            byte[] decode = Base64.getDecoder().decode(cf);
            fos.write(decode);
            System.out.println("Su p12 ha sido exportado con exito");
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void create_keystore(String path) {
        try {
            ks = KeyStore.getInstance("PKCS12");
            System.out.println("Introduzca la llave privada para acceder a su p12");
            String pass = sc.nextLine();
            password = pass.toCharArray();
            ks.load(new FileInputStream(path), password);
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
            e.printStackTrace();
        }
    }

    public static void open_p12_file() {
        Certificate cert;
        try {
            cert = ks.getCertificate("1");
            pk = cert.getPublicKey();
            p12_u = ((X509Certificate) cert).getSubjectDN().toString().split(",")[0].substring(13);
            email = ((X509Certificate) cert).getSubjectDN().toString().split(",")[1].substring(4);
            ed = new Date(((X509Certificate) cert).getNotBefore().getTime());
            vd = new Date(((X509Certificate) cert).getNotAfter().getTime());
        } catch (NullPointerException | KeyStoreException e) {
            e.printStackTrace();
        }
    }

    public static Connection connect() {
        Connection conn = null;
        try {
            conn = DriverManager.getConnection(url, user, BDpassword);
        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }
        return conn;
    }

    public static long db_flush(String[] data) {
        String sql = "insert into test (nombre, email, expedition_date, expire_date, public_key, p12_file) " +
                "values (?,?,?,?,?,?)";
        long id = 0;
        try (Connection conn = connect(); PreparedStatement pstmt = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {
            pstmt.setString(1, data[0]);
            pstmt.setString(2, data[1]);
            pstmt.setDate(3, ed);
            pstmt.setDate(4, vd);
            pstmt.setString(5, data[4]);
            pstmt.setString(6, data[5]);
            int ar = pstmt.executeUpdate();
            if (ar > 0) {
                try (ResultSet rs = pstmt.getGeneratedKeys()) {
                    if (rs.next()) {
                        id = rs.getLong(7);
                    }
                }
            }
        } catch (SQLException throwables) {
            throwables.printStackTrace();
        }
        return id;
    }

    public static void get_data(String sql) {
        try (Connection conn = connect(); Statement stmt = conn.createStatement(); ResultSet rs = stmt.executeQuery(sql)) {
            data(rs);
        } catch (SQLException throwables) {
            throwables.printStackTrace();
        }
    }

    public static String get_data(String sql, String c) {
        try (Connection conn = connect(); Statement stmt = conn.createStatement(); ResultSet rs = stmt.executeQuery(sql)) {
            return data1(rs, c);
        } catch (SQLException throwables) {
            throwables.printStackTrace();
        }
        return "";
    }

    public static void data(ResultSet rs) throws SQLException {
        while (rs.next()) {
            System.out.println(rs.getString("nombre") + "\t" + rs.getString("email") + "\t" + rs.getString("expedition_date") + "\t"
                    + rs.getString("expire_date") + "\t" + rs.getString("public_key") + "\t" + rs.getString("p12_file"));
        }
    }

    public static String data1(ResultSet rs, String c) throws SQLException {
        while (rs.next()) {
            return rs.getString(c);
        }
        return "";
    }


    //-------------------------------------------------------------------firmas---------------------------------------------------------------------------


    public static void sign_XML_document(String file_to_sign_path, String signed_file_path) {
        try {
            XMLSignatureFactory fac = get_XML_signature_factory();
            Reference ref = get_SHA1_document_transform_reference(fac);
            SignedInfo si = get_signed_info(fac, ref);
            KeyStore.PrivateKeyEntry keyEntry = load_p12();
            KeyInfo ki = get_key_x509c(keyEntry, fac);
            Document doc = load_document(file_to_sign_path);
            sign(doc, keyEntry, fac, si, ki);
            write_signed(doc, signed_file_path);
        } catch (InvalidAlgorithmParameterException | UnrecoverableEntryException | CertificateException | NoSuchAlgorithmException |
                KeyStoreException | IOException | ParserConfigurationException | SAXException | MarshalException e) {
            e.printStackTrace();
        } catch (XMLSignatureException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    public static XMLSignatureFactory get_XML_signature_factory() {
        return XMLSignatureFactory.getInstance("DOM");
    }

    public static Reference get_SHA1_document_transform_reference(XMLSignatureFactory fac) {
        try {
            return
                    fac.newReference(
                            "",
                            fac.newDigestMethod(DigestMethod.SHA1, null),
                            Collections.singletonList(fac.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null)),
                            null,
                            null
                    );
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static SignedInfo get_signed_info(XMLSignatureFactory fac, Reference ref) throws InvalidAlgorithmParameterException,
            NoSuchAlgorithmException {
        return
                fac.newSignedInfo(
                        fac.newCanonicalizationMethod(
                                CanonicalizationMethod.INCLUSIVE, (C14NMethodParameterSpec) null
                        ),
                        fac.newSignatureMethod(SignatureMethod.RSA_SHA1, null),
                        Collections.singletonList(ref)
                );
    }

    public static KeyStore.PrivateKeyEntry load_p12() throws KeyStoreException, IOException, CertificateException,
            NoSuchAlgorithmException, UnrecoverableEntryException {
        System.out.println("Entre la ruta de su p12");
        String p12_path = sc.nextLine();
        System.out.println("Entre su llave privada");
        String pass = sc.nextLine();
        ks1 = KeyStore.getInstance("PKCS12");
        ks1.load(new FileInputStream(p12_path), pass.toCharArray());
        return (KeyStore.PrivateKeyEntry) ks1.getEntry(ks1.aliases().nextElement(), new KeyStore.PasswordProtection(pass.toCharArray()));
    }

    public static KeyInfo get_key_x509c(KeyStore.PrivateKeyEntry keyEntry, XMLSignatureFactory fac) {
        X509Certificate cert = (X509Certificate) keyEntry.getCertificate();
        KeyInfoFactory kif = fac.getKeyInfoFactory();
        List x509_content = new ArrayList();
        x509_content.add(cert.getSubjectX500Principal().getName());
        x509_content.add(cert);
        pk = cert.getPublicKey();
        X509Data xd = kif.newX509Data(x509_content);
        return kif.newKeyInfo(Collections.singletonList(xd));
    }

    public static Document load_document(String file_to_sign_path) throws IOException, ParserConfigurationException, SAXException {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        return dbf.newDocumentBuilder().parse(new FileInputStream(file_to_sign_path));
    }

    public static void sign(Document doc, KeyStore.PrivateKeyEntry keyEntry, XMLSignatureFactory fac, SignedInfo si, KeyInfo ki)
            throws MarshalException, XMLSignatureException {
        DOMSignContext dsc;
        int p = -1;
        NodeList n = doc.getDocumentElement().getChildNodes();
        for (int i = 0; i < n.getLength(); i++) {
            if (n.item(i).getNodeName().equalsIgnoreCase("legalAuthenticator")) {
                p = i;
                break;
            }
        }
        if (p == -1) {
            dsc = new DOMSignContext(keyEntry.getPrivateKey(), doc.getDocumentElement(), doc.getDocumentElement().getLastChild());
        } else {
            dsc = new DOMSignContext(keyEntry.getPrivateKey(), doc.getDocumentElement(),
                    doc.getDocumentElement().getChildNodes().item(p).getNextSibling());
        }
        XMLSignature signature = fac.newXMLSignature(si, ki);
        signature.sign(dsc);
    }

    public static void write_signed(Document doc, String signed_file_path) throws Exception {
        OutputStream os = new FileOutputStream(signed_file_path);
        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer trans = tf.newTransformer();
        trans.transform(new DOMSource(doc), new StreamResult(os));
    }

//---------------------------------------------------------------validaciones-----------------------------------------------------------------------------

    public static boolean verify_signature(Document doc) {
        try {
            NodeList nodeList = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
            if (nodeList.getLength() == 0) {
                throw new DOMException(DOMException.INDEX_SIZE_ERR, "Signature");
            }
            DOMValidateContext validateContext = new DOMValidateContext(pk, doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature").item(0));
            XMLSignature signature = XMLSignatureFactory.getInstance("DOM").unmarshalXMLSignature(validateContext);
            return signature.validate(validateContext);
        } catch (Exception ignored) {

        }
        return false;
    }

    public static void verify_crl() {
        try {
            System.out.println("Introduzca la ruta de su p12");
            String path = sc.nextLine();
            create_keystore(path);
            TrustAnchor ta = new TrustAnchor(((X509Certificate) ks.getCertificate("1")).getSubjectDN().getName(), ks.getCertificate("1").getPublicKey(), null);
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());

            CertPathBuilder cpb = CertPathBuilder.getInstance("PKIX");
            PKIXRevocationChecker rc = (PKIXRevocationChecker) cpb.getRevocationChecker();
            rc.setOptions(
                    EnumSet.of(
                            PKIXRevocationChecker.Option.PREFER_CRLS,
                            PKIXRevocationChecker.Option.ONLY_END_ENTITY,
                            PKIXRevocationChecker.Option.NO_FALLBACK
                    )
            );

            PKIXBuilderParameters pkix_params = new PKIXBuilderParameters(ks, new X509CertSelector());
            pkix_params.addCertPathChecker(rc);
            tmf.init(new CertPathTrustManagerParameters(pkix_params));
            kmf.init(ks, password);

            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
        } catch (KeyStoreException | NoSuchAlgorithmException | InvalidAlgorithmParameterException | UnrecoverableKeyException | KeyManagementException e) {
            System.out.println(e.getMessage());
        }
    }
    public static void validate_OSCP(){

    }

    /*
    public static boolean is_cert_valid() {
        try{


            KeyStore kss = KeyStore.getInstance("JKS");
            System.out.println("Introduzca la ruta de su p12");
            String path = sc.nextLine();
            System.out.println("Introduzca su clave privada");
            char[] pass = sc.nextLine().toCharArray();
            InputStream in = new FileInputStream(path);
            kss.load(in, pass);

            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            ArrayList<X509Certificate> cert_list = new ArrayList<>();
            while (true){
                System.out.println("Introduzca la ruta del p12 a agregar");
                String p = sc.nextLine();

            }
            CertPath cp = cf.generateCertPath(cert_list);
            CertPathValidator cv = CertPathValidator.getInstance("PKIX");

            PKIXParameters params = new PKIXParameters(kss);
            params.setRevocationEnabled(true);

            Security.setProperty("ocsp.enable", "true");
            System.setProperty("com.sun.net.ssl.checkRenovation", "true");
            System.setProperty("com.sun.security.enableCRLDP", "true");

            PKIXCertPathValidatorResult r = (PKIXCertPathValidatorResult) cv.validate(cp, params);
            return true;

        } catch (CertificateException | NoSuchAlgorithmException | KeyStoreException | FileNotFoundException e) {
            System.err.println(e.getMessage());
        } catch (IOException e) {
            System.err.println(e.getMessage());
        } catch (InvalidAlgorithmParameterException e) {
            System.err.println(e.getMessage());
        } catch (CertPathValidatorException e) {
            System.err.println(e.getMessage());
        }
        return false;
    }

     */

}