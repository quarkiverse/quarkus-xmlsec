package io.quarkiverse.xmlsec.deployment;

import javax.crypto.spec.GCMParameterSpec;
import javax.xml.crypto.dsig.spec.XPathType;

import org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI;
import org.apache.xml.security.c14n.CanonicalizerSpi;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;
import org.apache.xml.security.transforms.TransformSpi;
import org.jboss.jandex.ClassInfo;
import org.jboss.jandex.DotName;
import org.jboss.jandex.IndexView;

import io.quarkus.deployment.annotations.BuildProducer;
import io.quarkus.deployment.annotations.BuildStep;
import io.quarkus.deployment.builditem.CombinedIndexBuildItem;
import io.quarkus.deployment.builditem.ExtensionSslNativeSupportBuildItem;
import io.quarkus.deployment.builditem.FeatureBuildItem;
import io.quarkus.deployment.builditem.IndexDependencyBuildItem;
import io.quarkus.deployment.builditem.nativeimage.NativeImageResourceBundleBuildItem;
import io.quarkus.deployment.builditem.nativeimage.NativeImageSecurityProviderBuildItem;
import io.quarkus.deployment.builditem.nativeimage.ReflectiveClassBuildItem;
import io.quarkus.deployment.builditem.nativeimage.RuntimeInitializedClassBuildItem;
import io.quarkus.deployment.builditem.nativeimage.RuntimeReinitializedClassBuildItem;

class XmlsecProcessor {

    private static final String FEATURE = "xmlsec";

    private static final DotName[] SPI_CLASSES = {
            DotName.createSimple(CanonicalizerSpi.class.getName()),
            DotName.createSimple(TransformSpi.class.getName())
    };

    @BuildStep
    FeatureBuildItem feature() {
        return new FeatureBuildItem(FEATURE);
    }

    @BuildStep
    ExtensionSslNativeSupportBuildItem activateSslNativeSupport() {
        return new ExtensionSslNativeSupportBuildItem(FEATURE);
    }

    @BuildStep
    IndexDependencyBuildItem indexDependencies() {
        return new IndexDependencyBuildItem("org.apache.santuario", "xmlsec");
    }

    @BuildStep
    void registerForReflection(BuildProducer<ReflectiveClassBuildItem> reflectiveClass,
            CombinedIndexBuildItem combinedIndex) {
        IndexView index = combinedIndex.getIndex();
        for (DotName spi : SPI_CLASSES) {
            for (ClassInfo subclass : index.getAllKnownSubclasses(spi)) {
                reflectiveClass.produce(new ReflectiveClassBuildItem(false, false, subclass.name().toString()));
            }
        }
        reflectiveClass.produce(new ReflectiveClassBuildItem(false, false,
                GCMParameterSpec.class.getName(), XPathType[].class.getName()));
    }

    @BuildStep
    void runtimeReinitializedClasses(BuildProducer<RuntimeReinitializedClassBuildItem> runtimeReinitializedClasses) {
        /* XMLSecurityConstants has a SecureRandom field initialized in a static initializer */
        runtimeReinitializedClasses.produce(new RuntimeReinitializedClassBuildItem(XMLSecurityConstants.class.getName()));
    }

    @BuildStep
    void runtimeInitializedClass(BuildProducer<RuntimeInitializedClassBuildItem> runtimeInitializedClass) {
        runtimeInitializedClass
                .produce(new RuntimeInitializedClassBuildItem("org.apache.xml.security.stax.impl.InboundSecurityContextImpl"));
    }

    @BuildStep
    NativeImageSecurityProviderBuildItem saslSecurityProvider() {
        return new NativeImageSecurityProviderBuildItem(XMLDSigRI.class.getName());
    }

    @BuildStep
    void resourceBundle(BuildProducer<NativeImageResourceBundleBuildItem> resourceBundle) {
        resourceBundle.produce(
                new NativeImageResourceBundleBuildItem("org.apache.xml.security.resource.xmlsecurity"));
    }

}
