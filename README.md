# mod_contact
An Apache httpd module that implements a contact us form with file upload.

## example
For an example of how the module is deployed, see the examples directory.

## directives
ContactStylesheet
: Set the XSLT stylesheet to be used when rendering the output.

ContactCommand
: Set to the name and path of the sendmail binary.

ContactArguments
: Set to arguments to pass to the sendmail binary.

ContactTo
: Expression resolving to the To address. Overridden by 'contact-header-to' in a form.

ContactToMatch
: Set to a regular expression that the To address must match.

ContactFrom
: Expression resolving to the From address. Overridden by 'contact-header-from' in a form.

ContactFromMatch
: Set to a regular expression that the From address must match.

ContactSender
: Expression resolving to the Sender email address. Overridden by 'contact-header-sender' in a form.

ContactReplyTo
: Expression resolving to the Reply-To email address. Overridden by 'contact-header-replyto' in a form.

## form fields
The order of form fields are significant. Headers fields must be sent first, followed by body fields, followed by attachment/inline fields. Fields sent out of order are ignored.

### headers
contact-header-to
: Set to the To address. If set in a form, this address must match the regex in ContactToMatch.

contact-header-from
: Set to the From address. If set in a form, this address must match the regex in ContactFromMatch.

contact-header-sender
: Set to the Sender address.

contact-header-replyto
: Set to the Reply-To address.

contact-header-subject
: Set to the Subject of the message.

### body
contact-body-*
: Set to any field you want to appear in the body of the message. May be specified many times.

### attachments
contact-attachment-*
: Set to any file you want to upload and add to the email as an attachment.

contact-inline-*
: Set to any file you want to upload and add to the email as an inline attachment.

