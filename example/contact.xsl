<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:contact="https://github.com/minfrin/mod_contact" xmlns="http://www.w3.org/1999/xhtml" version="1.0">
<xsl:output doctype-system="about:legacy-compat" method="html"/>
<xsl:template match="/contact:contact">
<html> 

  <head>
    <title></title> 
  </head> 

  <body>

<xsl:choose>                    
<xsl:when test="contact:message">
    <h2><xsl:value-of select="contact:message" /></h2>
    <p><xsl:value-of select="contact:status" /></p>
</xsl:when>
<xsl:otherwise>                 
    <h2>Enter your message</h2>
</xsl:otherwise>
</xsl:choose>

    <form action="" method="POST" enctype="multipart/form-data">

    <p>
      <label>Email</label><input type="text" name="contact-header-replyto"><xsl:attribute name="value"><xsl:value-of select="contact:form/contact:input[@name='contact-header-replyto']" /></xsl:attribute></input>
    </p>
    <p>
      <label>Subject</label><input type="text" name="contact-header-subject"><xsl:attribute name="value"><xsl:value-of select="contact:form/contact:input[@name='contact-header-subject']" /></xsl:attribute></input>
    </p>
    <p>
      <label>Name</label><input type="text" name="contact-body-name"><xsl:attribute name="value"><xsl:value-of select="contact:form/contact:input[@name='contact-body-name']" /></xsl:attribute></input>
    </p>
    <p>
      <label>Message</label><textarea name="contact-body-message"><xsl:value-of select="contact:form/contact:input[@name='contact-body-message']" /></textarea>
    </p>
    <p>
      <input type="file" name="contact-attachment-file" />
    </p>
    <p>
      <input type="submit" name="submit" value="Submit" />
    </p>
  </form>

  </body>
</html>
</xsl:template>
</xsl:stylesheet>

