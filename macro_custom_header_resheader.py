import json
import sys
from java.io import PrintWriter
from burp import IBurpExtender
from burp import ISessionHandlingAction


class BurpExtender(IBurpExtender, ISessionHandlingAction):

    def getActionName(self):
        # return extension name
        return 'Custom Header For Macro - Header '

    def registerExtenderCallbacks(self, callbacks):
        # set extension name
        callbacks.setExtensionName('Custom Header For Macro - Header')

        # register for scanner callbacks
        callbacks.registerSessionHandlingAction(self)

        # make errors more readable ad required for debugger burp-exceptions
        sys.stdout = callbacks.getStdout()

        # use PrintWriter for all output
        self.stdout = PrintWriter(callbacks.getStdout(), True)
        self.stderr = PrintWriter(callbacks.getStdout(), True)

        # write a message to output stream
        self.stdout.println('Custom Header For Macro - Header')

        # keep reference to the callbacks
        self.callbacks = callbacks

        # obtain extension to the helper object
        self.helpers = callbacks.getHelpers()

    def performAction(self, baseRequestResponse, macroItems):
        # analyse request to be modified
        request_info = self.helpers.analyzeRequest(baseRequestResponse)
        # get the first response from a macro item

        macro_response_info = self.helpers.analyzeResponse(macroItems[0].getResponse())

        self.stdout.println('Loading custom header for Macro complete: By justm0rph3u5')

        # get the list of headers from the response, if token is present in the response header then we need to list all the header and extract the value

        macro_body_offset = macro_response_info.getHeaders()


        #from the macro body(which contains the response headers), we are extracting dynamic value of the header
        new_header = macro_body_offset.get(1)[14:]


        #To list all the headers and iterate one by one to
        headers = request_info.getHeaders()
        head_delete = ''

        for header in headers:



            #Change this value according to the custom header present in the request. So if X-SESSION_ID: xxxxxxxx is the header then change the string to 'X_SESSION_ID'
            if 'X-CSRF' in header:
                head_delete = header

        #remove the header
        headers.remove(head_delete)

        #add new header, some wierd java error may come. please diy
        #While adding the new header, kindly change the value to 'X_SESSION_ID', from above example.

        headers.add('X-CSRF: ' + new_header)

        # get body and add headers to make final request
        message = baseRequestResponse.getRequest()
        body_offset = request_info.getBodyOffset()
        message_body = message[body_offset:-1]

        # create new message with headers and body
        new_message_request = self.helpers.buildHttpMessage(headers, message_body)

        baseRequestResponse.setRequest(new_message_request)

#Blog to implement this https://justm0rph3u5.medium.com/