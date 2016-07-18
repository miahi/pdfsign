/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ro.miahi.pdf;


import java.io.*;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Collection;
import java.util.Date;

import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.cos.COSString;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.tsp.TSPValidationException;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.StoreException;

/**
 * PDF Signature verification with Apache PDFBox
 */
public final class TestPdfBox
{
    private SimpleDateFormat sdf = new SimpleDateFormat("dd.MM.yyyy HH:mm:ss");

    private static PrintStream out = System.out;
//    private static PrintStream out = new PrintStream(new ByteArrayOutputStream());

    private TestPdfBox()
    {
    }

    /**
     * This is the entry point for the application.
     *
     * @param args The command-line arguments.
     *
     * @throws IOException If there is an error reading the file.
     * @throws CertificateException
     * @throws java.security.NoSuchAlgorithmException
     * @throws java.security.InvalidKeyException
     * @throws java.security.NoSuchProviderException
     * @throws java.security.SignatureException
     */
    public static void main(String[] args) throws Exception
    {
        TestPdfBox show = new TestPdfBox();
        show.showSignature( args );
    }

    private void showSignature(String[] args) throws Exception
    {

//            String infile = "Document cu discount 100%_signed.pdf";
            String infile = "Document cu discount 100%_signed_mod2.pdf";
//        String infile = "SampleSignedPDFDocument.pdf";

        PDDocument document = null;
        try
        {
            document = PDDocument.load(new File(infile));
            for (PDSignature sig : document.getSignatureDictionaries())
            {

                COSDictionary sigDict = sig.getCOSObject();
                COSString contents = (COSString) sigDict.getDictionaryObject(COSName.CONTENTS);

                // download the signed content
                FileInputStream fis = new FileInputStream(infile);
                byte[] buf = null;
                try
                {
                    buf = sig.getSignedContent(fis);
                }
                finally
                {
                    fis.close();
                }

                out.println("\n\nSignature found");
                out.println("Name:     " + sig.getName());
                out.println("Modified: " + sdf.format(sig.getSignDate().getTime()));
                String subFilter = sig.getSubFilter();
                if (subFilter != null)
                {
                    if (subFilter.equals("adbe.pkcs7.detached"))
                    {
                        verifyPKCS7(buf, contents, sig);

                        //TODO check certificate chain, revocation lists


                    }
                    else if (subFilter.equals("adbe.pkcs7.sha1"))
                    {
                        // example: PDFBOX-1452.pdf
                        COSString certString = (COSString) sigDict.getDictionaryObject(
                                COSName.CONTENTS);
                        byte[] certData = certString.getBytes();
                        CertificateFactory factory = CertificateFactory.getInstance("X.509");
                        ByteArrayInputStream certStream = new ByteArrayInputStream(certData);
                        Collection<? extends Certificate> certs = factory.generateCertificates(certStream);
                        out.println("certs=" + certs);

                        byte[] hash = MessageDigest.getInstance("SHA1").digest(buf);
                        verifyPKCS7(hash, contents, sig);

                        //TODO check certificate chain, revocation lists, timestamp...
                    }
                    else if (subFilter.equals("adbe.x509.rsa_sha1"))
                    {
                        // example: PDFBOX-2693.pdf
                        COSString certString = (COSString) sigDict.getDictionaryObject(
                                COSName.getPDFName("Cert"));
                        byte[] certData = certString.getBytes();
                        CertificateFactory factory = CertificateFactory.getInstance("X.509");
                        ByteArrayInputStream certStream = new ByteArrayInputStream(certData);
                        Collection<? extends Certificate> certs = factory.generateCertificates(certStream);
                        out.println("certs=" + certs);

                        out.println("TODO X509 check");

                        //TODO verify signature
                    }
                    else
                    {
                        System.err.println("Unknown certificate type: " + subFilter);
                    }
                }
                else
                {
                    throw new IOException("Missing subfilter for cert dictionary");
                }
            }
        }
        catch (CMSException ex)
        {
            throw new IOException(ex);
        }
        catch (OperatorCreationException ex)
        {
            throw new IOException(ex);
        }
        finally
        {
            if (document != null)
            {
                document.close();
            }
        }

    }

    /**
     * Verify a PKCS7 signature.
     *
     * @param byteArray the byte sequence that has been signed
     * @param contents the /Contents field as a COSString
     * @param sig the PDF signature (the /V dictionary)
     * @throws CertificateException
     * @throws CMSException
     * @throws StoreException
     * @throws OperatorCreationException
     */
    private void verifyPKCS7(byte[] byteArray, COSString contents, PDSignature sig)
            throws Exception {
        // inspiration:
        // http://stackoverflow.com/a/26702631/535646
        // http://stackoverflow.com/a/9261365/535646
        CMSProcessable signedContent = new CMSProcessableByteArray(byteArray);
        CMSSignedData signedData = new CMSSignedData(signedContent, contents.getBytes());
        Store certificatesStore = signedData.getCertificates();
        Collection<SignerInformation> signers = signedData.getSignerInfos().getSigners();
        SignerInformation signerInformation = signers.iterator().next();
        Collection matches = certificatesStore.getMatches(signerInformation.getSID());
        X509CertificateHolder certificateHolder = (X509CertificateHolder) matches.iterator().next();
        X509Certificate certFromSignedData = new JcaX509CertificateConverter().getCertificate(certificateHolder);
        out.println(" certFromSignedData: " + certFromSignedData);

        // check timestamp
        if( signerInformation.getUnsignedAttributes() != null) {
            Attribute at = signerInformation.getUnsignedAttributes().get(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken);
            if(at != null) {
                DERSequence ds = (DERSequence) at.getAttributeValues()[0];
                ASN1Primitive ap = ds.toASN1Primitive();
                CMSSignedData sd = new CMSSignedData(ap.getEncoded());

                Date tspTime = checkTimestamp(sd);
                out.println(" TSP time:  " + tspTime);
                out.println(" Sign time: " + sig.getSignDate().getTime());
            }
        }

        certFromSignedData.checkValidity(sig.getSignDate().getTime());

        if (signerInformation.verify(new JcaSimpleSignerInfoVerifierBuilder().build(certFromSignedData)))
        {
            out.println("+++ Signature verified");
        }
        else
        {
            out.println("Signature verification failed");
        }
    }

    /**
     * Checks timestamp (RFC 3161)
     * @param sd
     */
    private Date checkTimestamp(CMSSignedData sd) throws Exception {
        Store certificatesStore = sd.getCertificates();
        Collection<SignerInformation> signers = sd.getSignerInfos().getSigners();
        SignerInformation signerInformation = signers.iterator().next();
        Collection matches = certificatesStore.getMatches(signerInformation.getSID());
        X509CertificateHolder certificateHolder = (X509CertificateHolder) matches.iterator().next();
        X509Certificate certFromSignedData = new JcaX509CertificateConverter().getCertificate(certificateHolder);
        out.println(" TIME certFromSignedData: " + certFromSignedData);

        sd.getSignedContent().getContent();
        TimeStampToken tst = new TimeStampToken(sd);

        try {
            tst.validate(new JcaSimpleSignerInfoVerifierBuilder().build(certFromSignedData));
            out.println(" TSP validation successful");

            out.println(" TSP serial number: " + tst.getTimeStampInfo().getSerialNumber());
            out.println(" TSP policy: " + tst.getTimeStampInfo().getPolicy());
            out.println(" TSP TSA: " + tst.getTimeStampInfo().getTsa());
            out.println(" TSP hash: " + tst.getTimeStampInfo().getHashAlgorithm().getAlgorithm());

            return tst.getTimeStampInfo().getGenTime();

        } catch (TSPValidationException e){
            out.println(" TSP validation failed");
            return null;
        }

    }

}
