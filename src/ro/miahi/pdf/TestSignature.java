package ro.miahi.pdf;

import com.fasterxml.jackson.databind.ObjectMapper;
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
            String json = ts.verifyPdf();
            System.out.println(json);
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

    public String verifyPdf() throws Exception {

        // todo: populate the keystore
        KeyStore kall = PdfPKCS7.loadCacertsKeyStore();

        PdfReader reader = new PdfReader(fileName);
        AcroFields af = reader.getAcroFields();

        // Search of the whole signature
        ArrayList<String> names = af.getSignatureNames();

        HashMap response = new HashMap();

        for (String name : names) {
            HashMap signature = new HashMap();
            response.put(name, signature);
            // Name
            signature.put("signature_name", name);
            signature.put("whole_document", af.signatureCoversWholeDocument(name));
            // Doc info
            signature.put("revision", af.getRevision(name));
            signature.put("total_revisions", af.getTotalRevisions());
            PdfPKCS7 pk = af.verifySignature(name);
            Calendar cal = pk.getSignDate();
            Certificate pkc[] = pk.getCertificates();

            // Information about the certificate and signature
            signature.put("signature_subject", PdfPKCS7.getSubjectFields(pk.getSigningCertificate()).toString());
            signature.put("modified", !pk.verify());
            signature.put("sign_date", cal.getTime());
            signature.put("sign_reason", pk.getReason());

            // Information about timestamps
            if (pk.verifyTimestampImprint()) {
                signature.put("TSD", pk.getTimeStampDate().getTime());
                signature.put("TSA", pk.getTimeStampToken().getTimeStampInfo().getTsa().toString());
            }

            // Can it be verified?
            Object fails[] = PdfPKCS7.verifyCertificates(pkc, kall, null, cal);
            if (fails == null) {
                signature.put("verified", true);
            } else {
                signature.put("verified", false);
                signature.put("verify_fails", fails[1].toString());
            }
        }

        reader.close();

        return toJson(response);
    }

    public void setFileName(String fileName) {
        this.fileName = fileName;
    }

    private String toJson(Object obj) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        String json = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(obj);
        return json;
    }
}