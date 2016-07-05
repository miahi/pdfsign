package ro.miahi.pdf;

import com.lowagie.text.ExceptionConverter;
import com.lowagie.text.pdf.AcroFields;
import com.lowagie.text.pdf.PdfPKCS7;
import com.lowagie.text.pdf.PdfReader;
import com.lowagie.text.pdf.PdfStamper;

import java.io.FileOutputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.HashMap;
import java.util.Iterator;

public class TestSignature {

    private String fileName;

    public static void main(String[] args) {
        try {
            TestSignature ts = new TestSignature();
            ts.setFileName("SampleSignedPDFDocument.pdf");
            ts.verifyPdf();
            ts.setFileName("OoPdfFormExample.pdf");
            ts.fillForm();
        } catch (Exception e) {
            System.err.println(e.getMessage());
        }
    }

    public void fillForm() throws Exception {
        PdfReader reader = new PdfReader(fileName);
        String outputFileName = fileName + "_out.pdf";

        PdfStamper stamp = new PdfStamper(reader, new FileOutputStream(outputFileName));

        AcroFields form = stamp.getAcroFields();

        HashMap formFields = form.getFields();
        Iterator iterator = formFields.keySet().iterator();
        System.out.println("Found fields: ");
        while (iterator.hasNext()) {
            String field = (String) iterator.next();
            System.out.println("  Field >" + field + "<");
            form.setField(field, "1");
        }

        stamp.setFormFlattening(true);
        stamp.close();

    }

    public boolean verifyPdf() throws Exception {

        // todo: populate the keystore
        KeyStore kall = PdfPKCS7.loadCacertsKeyStore();

        PdfReader reader = new PdfReader(fileName);
        AcroFields af = reader.getAcroFields();

        // Search of the whole signature
        ArrayList<String> names = af.getSignatureNames();

        for (String name : names) {
            // Name
            System.out.println("Signature name: " + name);
            System.out.println("Signature covers whole document: " + af.signatureCoversWholeDocument(name));
            // Doc info
            System.out.println("Document revision: " + af.getRevision(name) + " of " + af.getTotalRevisions());

            PdfPKCS7 pk = af.verifySignature(name);
            Calendar cal = pk.getSignDate();
            Certificate pkc[] = pk.getCertificates();

            // Information about the certificate and signature
            System.out.println("Subject: " + PdfPKCS7.getSubjectFields(pk.getSigningCertificate()));
            // Was the doc modified
            System.out.println("Document modified: " + !pk.verify());
            System.out.println("Sign date: " + cal.getTime());
            System.out.println("Reason: " + pk.getReason());

            // Information about timestamps
            if (pk.verifyTimestampImprint()) {
                System.out.println("TSD " + pk.getTimeStampDate().getTime());
                System.out.println("TSA " + pk.getTimeStampToken().getTimeStampInfo().getTsa().toString());
            } else {
                System.out.println("Timestamp not verified");
            }

            // Can it be verified?
            Object fails[] = PdfPKCS7.verifyCertificates(pkc, kall, null, cal);
            if (fails == null)
                System.out.println("Certificates verified against the KeyStore");
            else
                System.out.println("Certificate verification failed: " + fails[1]);
        }

        reader.close();
        return true;
    }

    public void setFileName(String fileName) {
        this.fileName = fileName;
    }
}