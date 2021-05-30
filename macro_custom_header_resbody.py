import json
import sys
from java.io import PrintWriter
from burp import IBurpExtender
from burp import IHttpRequestResponse
from burp import IHttpService
from burp import ISessionHandlingAction
import re

#Regex for extracting value of the token from the HTML Body

#Modify this
regex = r"value=\'\S+\'"


class BurpExtender(IBurpExtender, ISessionHandlingAction):

    def getActionName(self):
        # return extension name
        return 'Custom Header For Macro - Body'

    def registerExtenderCallbacks(self, callbacks):
        # set extension name
        callbacks.setExtensionName('Custom Header For Macro - Body')

        # register for scanner callbacks
        callbacks.registerSessionHandlingAction(self)

        # make errors more readable ad required for debugger burp-exceptions
        sys.stdout = callbacks.getStdout()

        # use PrintWriter for all output
        self.stdout = PrintWriter(callbacks.getStdout(), True)
        self.stderr = PrintWriter(callbacks.getStdout(), True)

        # write a message to output stream
        self.stdout.println('Custom Header For Macro - Body')

        # keep reference to the callbacks
        self.callbacks = callbacks

        # obtain extension to the helper object
        self.helpers = callbacks.getHelpers()

    def performAction(self, baseRequestResponse, macroItems):
        # analyse request to be modified
        request_details = self.helpers.analyzeRequest(baseRequestResponse)
        # get the first response from a macro item

        macro_response = self.helpers.analyzeResponse(macroItems[0].getResponse())

        self.stdout.println('Loading custom header for Macro complete: By justm0rph3u5')

        # extract the token from the macro response
        macro_message = macroItems[0].getResponse()

        # print(self.helpers.bytesToString(macro_message))

        #this part of the code deals with fetching value of HTML Response Body

        macro_offset = macro_response.getBodyOffset()

        macro_body_value = macro_message[macro_offset:-1]
        macro_body_str = self.helpers.bytesToString(macro_body_value)

        #Regex checks the value of the Token to be fetched from the html body. Here is was csrf token in the response body. Modify regex and slice it accordingly

        matched = re.finditer(regex, macro_body_str, re.MULTILINE)

        for matchNum, match_1 in enumerate(matched, start=1):

            #change this value of index according to the regex.

            #Modify this
            new_header=match_1.group()[7:-1]

            # get headers from base request
            headers = request_details.getHeaders()

            # ref to existing header
            head_delete = ''

            # Change this value according to the custom header present in the request. So if X-SESSION_ID: xxxxxxxx is the header then change the string to 'X_SESSION_ID'
            for header in headers:
                if 'X-CSRF' in header:
                    head_delete = header

            headers.remove(head_delete)

            # add new header, some wierd java error may come. please diy
            # While adding the new header, kindly change the value to 'X_SESSION_ID', from above example.
            headers.add('X-CSRF: ' + new_header)

            # get body and add headers
            message = baseRequestResponse.getRequest()
            body_offset = request_details.getBodyOffset()
            message_body = message[body_offset:-1]

            # create new message with headers and body
            new_message_request = self.helpers.buildHttpMessage(headers, message_body)

            baseRequestResponse.setRequest(new_message_request)

#Blog to implement this https://justm0rph3u5.medium.com/ 