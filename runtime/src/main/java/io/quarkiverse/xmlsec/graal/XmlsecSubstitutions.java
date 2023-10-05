package io.quarkiverse.xmlsec.graal;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.stream.XMLOutputFactory;

import org.apache.xml.security.exceptions.XMLSecurityException;

import com.oracle.svm.core.annotate.Alias;
import com.oracle.svm.core.annotate.RecomputeFieldValue;
import com.oracle.svm.core.annotate.Substitute;
import com.oracle.svm.core.annotate.TargetClass;

/**
 * A workaround for https://issues.apache.org/jira/browse/SANTUARIO-606
 */
@TargetClass(className = "org.apache.xml.security.stax.ext.XMLSecurityConstants")
final class XMLSecurityConstants {

    @Alias
    @RecomputeFieldValue(kind = RecomputeFieldValue.Kind.FromAlias)
    private static SecureRandom SECURE_RANDOM;
    @Alias
    @RecomputeFieldValue(kind = RecomputeFieldValue.Kind.FromAlias)
    public static DatatypeFactory datatypeFactory;
    @Alias
    @RecomputeFieldValue(kind = RecomputeFieldValue.Kind.FromAlias)
    public static XMLOutputFactory xmlOutputFactory;
    @Alias
    @RecomputeFieldValue(kind = RecomputeFieldValue.Kind.FromAlias)
    public static XMLOutputFactory xmlOutputFactoryNonRepairingNs;

    static {
        try {
            datatypeFactory = DatatypeFactory.newInstance();
        } catch (DatatypeConfigurationException e) {
            throw new RuntimeException(e);
        }

        xmlOutputFactory = XMLOutputFactory.newInstance();
        xmlOutputFactory.setProperty(XMLOutputFactory.IS_REPAIRING_NAMESPACES, true);

        xmlOutputFactoryNonRepairingNs = XMLOutputFactory.newInstance();
        xmlOutputFactoryNonRepairingNs.setProperty(XMLOutputFactory.IS_REPAIRING_NAMESPACES, false);
    }

    @Substitute
    public static byte[] generateBytes(int length) throws XMLSecurityException {

        SecureRandom rnd = SECURE_RANDOM;
        if (rnd == null) {
            synchronized (XMLSecurityConstants.class) {
                rnd = SECURE_RANDOM;
                if (rnd == null) {
                    try {
                        String PrngAlgorithm = System.getProperty("org.apache.xml.security.securerandom.algorithm");
                        SECURE_RANDOM = rnd = PrngAlgorithm != null ? SecureRandom.getInstance(PrngAlgorithm)
                                : new SecureRandom();
                    } catch (NoSuchAlgorithmException e) {
                        throw new RuntimeException(e);
                    }
                }
            }
        }

        try {
            byte[] temp = new byte[length];
            rnd.nextBytes(temp);
            return temp;
        } catch (Exception ex) {
            throw new XMLSecurityException(ex);
        }
    }

}

public class XmlsecSubstitutions {
}
