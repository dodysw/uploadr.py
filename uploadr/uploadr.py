#!/usr/bin/env python

"""
   uploadr.py

   Upload images placed within a directory to your Flickr account.

   Requires:
       xmltramp http://www.aaronsw.com/2002/xmltramp/
       flickr account http://flickr.com

   Inspired by:
        http://micampe.it/things/flickruploadr

   Usage:

   The best way to use this is to just fire this up in the background and forget about it.
   If you find you have CPU/Process limits, then setup a cron job.

   %nohup python uploadr.py -d &

   cron entry (runs at the top of every hour )
   0  *  *   *   * /full/path/to/uploadr.py > /dev/null 2>&1

   September 2005
   Cameron Mallory   cmallory/berserk.org

   This code has been updated to use the new Auth API from flickr.

   You may use this code however you see fit in any form whatsoever.

   July 2013 Dody Suria Wijaya - upload is now performed asynchronously.


"""

import argparse
import hashlib
import mimetools
import mimetypes
import os
import shelve
import string
import sys
import time
import urllib2
import webbrowser
import xmltramp

#
##
##  Items you will want to change
##

#
# Location to scan for new images
#
IMAGE_DIR = "images/"
#
#   Flickr settings
#
FLICKR = {"title": "",
        "description": "",
        "tags": "auto-upload",
        "is_public": "0",
        "is_friend": "0",
        "is_family": "0",
        "hidden": "2",
        }
#
#   How often to check for new images to upload (in seconds)
#
SLEEP_TIME = 1 * 60
#
#   Only with --drip-feed option:
#     How often to wait between uploading individual images (in seconds)
#
DRIP_TIME = 1 * 60
#
#   Check tickets status every X uploads. Depending photo size, tt takes 
#   roughly 2-5 seconds for Flickr to parse uploaded photo. 
TICKET_CHECK_EVERY = 5
#
#   File we keep the history of uploaded images in.
#
HISTORY_FILE = os.path.join(IMAGE_DIR, "uploadr.history")

##
##  You shouldn't need to modify anything below here
##
FLICKR["api_key"] = os.environ['FLICKR_UPLOADR_PY_API_KEY']
FLICKR["secret"] = os.environ['FLICKR_UPLOADR_PY_SECRET']

class APIConstants:
    """ APIConstants class
    """

    base = "http://ycpi.api.flickr.com/services/"
    rest   = base + "rest/"
    auth   = base + "auth/"
    upload = "http://up.flickr.com/services/upload/"

    token = "auth_token"
    secret = "secret"
    key = "api_key"
    sig = "api_sig"
    frob = "frob"
    perms = "perms"
    method = "method"

    def __init__( self ):
       """ Constructor
       """
       pass

api = APIConstants()

class Uploadr:
    """ Uploadr class
    """

    token = None
    perms = ""
    TOKEN_FILE = os.path.join(IMAGE_DIR, ".flickrToken")

    def __init__( self ):
        """ Constructor
        """
        self.token = self.getCachedToken()



    def signCall( self, data):
        """
        Signs args via md5 per http://www.flickr.com/services/api/auth.spec.html (Section 8)
        """
        keys = data.keys()
        keys.sort()
        foo = ""
        for a in keys:
            foo += (a + data[a])

        f = FLICKR[ api.secret ] + api.key + FLICKR[ api.key ] + foo
        #f = api.key + FLICKR[ api.key ] + foo
        return hashlib.md5( f ).hexdigest()

    def urlGen( self , base,data, sig = None):
        """ urlGen
        """
        foo = base + "?"
        for d in data:
            foo += d + "=" + data[d] + "&"
        foo += api.key + "=" + FLICKR[ api.key ] 
        if sig is not None:
            foo += "&" + api.sig + "=" + sig
        return foo

    def authenticate( self ):
        """ Authenticate user so we can upload images
        """

        print("Getting new token")
        self.getFrob()
        self.getAuthKey()
        self.getToken()
        self.cacheToken()

    def getFrob( self ):
        """
        flickr.auth.getFrob

        Returns a frob to be used during authentication. This method call must be
        signed.

        This method does not require authentication.
        Arguments

        api.key (Required)
        Your API application key. See here for more details.
        """

        d = {
            api.method  : "flickr.auth.getFrob"
            }
        sig = self.signCall( d )
        url = self.urlGen( api.rest, d, sig )
        try:
            response = self.getResponse( url )
            if ( self.isGood( response ) ):
                FLICKR[ api.frob ] = str(response.frob)
            else:
                self.reportError( response )
        except:
            print("Error getting frob:" + str( sys.exc_info() ))

    def getAuthKey( self ):
        """
        Checks to see if the user has authenticated this application
        """
        d =  {
            api.frob : FLICKR[ api.frob ],
            api.perms : "write"
            }
        sig = self.signCall( d )
        url = self.urlGen( api.auth, d, sig )
        ans = ""
        try:
            webbrowser.open( url )
            ans = raw_input("Have you authenticated this application? (Y/N): ")
        except:
            print(str(sys.exc_info()))
        if ( ans.lower() == "n" ):
            print("You need to allow this program to access your Flickr site.")
            print("A web browser should pop open with instructions.")
            print("After you have allowed access restart uploadr.py")
            sys.exit()

    def getToken( self ):
        """
        http://www.flickr.com/services/api/flickr.auth.getToken.html

        flickr.auth.getToken

        Returns the auth token for the given frob, if one has been attached. This method call must be signed.
        Authentication

        This method does not require authentication.
        Arguments

        NTC: We need to store the token in a file so we can get it and then check it insted of
        getting a new on all the time.

        api.key (Required)
           Your API application key. See here for more details.
        frob (Required)
           The frob to check.
        """

        d = {
            api.method : "flickr.auth.getToken",
            api.frob : str(FLICKR[ api.frob ])
        }
        sig = self.signCall( d )
        url = self.urlGen( api.rest, d, sig )
        try:
            res = self.getResponse( url )
            if ( self.isGood( res ) ):
                self.token = str(res.auth.token)
                self.perms = str(res.auth.perms)
                self.cacheToken()
            else :
                self.reportError( res )
        except:
            print(str(sys.exc_info()))

    def getCachedToken( self ):
        """
        Attempts to get the flickr token from disk.
       """
        if ( os.path.exists( self.TOKEN_FILE )):
            return open( self.TOKEN_FILE ).read()
        else :
            return None



    def cacheToken( self ):
        """ cacheToken
        """

        try:
            open( self.TOKEN_FILE , "w").write( str(self.token) )
        except:
            print("Issue writing token to local cache ", str(sys.exc_info()))

    def checkToken( self ):
        """
        flickr.auth.checkToken

        Returns the credentials attached to an authentication token.
        Authentication

        This method does not require authentication.
        Arguments

        api.key (Required)
            Your API application key. See here for more details.
        auth_token (Required)
            The authentication token to check.
        """

        if ( self.token == None ):
            return False
        else :
            d = {
                api.token  :  str(self.token) ,
                api.method :  "flickr.auth.checkToken"
            }
            sig = self.signCall( d )
            url = self.urlGen( api.rest, d, sig )
            try:
                res = self.getResponse( url )
                if ( self.isGood( res ) ):
                    self.token = res.auth.token
                    self.perms = res.auth.perms
                    return True
                else :
                    self.reportError( res )
            except:
                print(str(sys.exc_info()))
            return False


    def upload( self ):
        """ upload
        """

        newImages = self.grabNewImages()
        if ( not self.checkToken() ):
            self.authenticate()
        self.uploaded = shelve.open( HISTORY_FILE )
        tickets = {}
        totalImages = len(newImages)
        for i, image in enumerate( newImages ):
            success, ticketId = self.uploadImage( image )
            if success:
                print("Uploaded %s of %s." % (i+1, totalImages))
                if args.drip_feed and i != len( newImages )-1:
                    tickets = self.processTickets(tickets)
                    print("Waiting " + str(DRIP_TIME) + " seconds before next upload")
                    time.sleep( DRIP_TIME )
                elif (i+1) % TICKET_CHECK_EVERY == 0:
                    tickets = self.processTickets(tickets)
                tickets[ticketId] = {"image": image, "photoId": None}

        while tickets:
            tickets = self.processTickets(tickets)
            if tickets:
                time.sleep(5)

        self.uploaded.close()

    def processTickets(self, tickets):
        """ Iterate collected tickets for completed uploads and handle the photo id
        """

        tickets = self.checkTickets(tickets)
        for ticketId in [ tid for tid in tickets if tickets[tid]["photoId"] is not None]:
            ticket = tickets[ticketId]
            self.logUpload( ticket["photoId"], ticket["image"] )
            if args.sets:
                self.addPhotoToSet( ticket["photoId"], args.sets )
            del tickets[ticketId]
        return tickets

    def grabNewImages( self ):
        """ grabNewImages
        """

        images = []
        foo = os.walk( IMAGE_DIR )
        for data in foo:
            (dirpath, dirnames, filenames) = data
            for f in filenames :
                ext = f.lower().split(".")[-1]
                if ( ext == "jpg" or ext == "gif" or ext == "png" ):
                    images.append( os.path.normpath( dirpath + "/" + f ) )
        images.sort()
        return images


    def uploadImage( self, image ):
        """ uploadImage
        """

        success = False
        ticketId = None
        if ( not self.uploaded.has_key( image ) ):
            print("Uploading " + image + "...")
            try:
                photo = ('photo', image, open(image,'rb').read())
                if args.title: # Replace
                    FLICKR["title"] = args.title
                if args.description: # Replace
                    FLICKR["description"] = args.description
                if args.tags: # Append
                    FLICKR["tags"] += " " + args.tags + " "
                d = {
                    api.token       : str(self.token),
                    api.perms       : str(self.perms),
                    "title"         : str( FLICKR["title"] ),
                    "description"   : str( FLICKR["description"] ),
                    "tags"          : str( FLICKR["tags"] ),
                    "is_public"     : str( FLICKR["is_public"] ),
                    "is_friend"     : str( FLICKR["is_friend"] ),
                    "is_family"     : str( FLICKR["is_family"] ),
                    "async"         : "1"
                }
                sig = self.signCall( d )
                d[ api.sig ] = sig
                d[ api.key ] = FLICKR[ api.key ]
                url = self.build_request(api.upload, d, (photo,))
                xml = urllib2.urlopen( url ).read()
                res = xmltramp.parse(xml)
                if ( self.isGood( res ) ):
                    ticketId = str( res.ticketid )
                    success = True
                else :
                    print("Problem:")
                    self.reportError( res )
            except:
                print(str(sys.exc_info()))
        return success, ticketId

    def addPhotoToSet( self, photoId, setId ):
        """ add image to a set
        """

        success = False
        print("Adding " + photoId + " to set# " + setId + "...")
        d = {
            api.token       : str(self.token),
            api.perms       : str(self.perms),
            api.method      : "flickr.photosets.addPhoto",
            "photoset_id"   : args.sets,
            "photo_id"      : photoId,
        }
        sig = self.signCall( d )
        url = self.urlGen( api.rest, d, sig )
        try:
            res = self.getResponse( url )
            if ( self.isGood( res ) ):
                success = True
                print("Success.")
            else :
                print("Problem:")
                self.reportError( res )
        except:
            print(str(sys.exc_info()))
        return success

    def checkTickets( self, tickets):
        """ Check tickets status and return successful and pending tickets.
        """
        if not tickets:
            return tickets

        ticketIds = ",".join(tickets.keys())
        print("Checking %s tickets ..." % len(tickets))
        d = {
            api.method  : "flickr.photos.upload.checkTickets",
            "tickets"   : ticketIds,
        }
        url = self.urlGen( api.rest, d )
        try:
            res = self.getResponse( url )
            if ( self.isGood( res ) ):
                for ticket in res.uploader:
                    completed = "complete" in ticket()
                    if "invalid" in ticket() or (completed and ticket("complete") == 2):
                        print("Ticket " + ticket("id") + " failed.")
                        del tickets[ticket("id")]
                    elif completed and ticket("complete") == "1":
                        tickets[ticket("id")]["photoId"] = ticket("photoid")
            else :
                print("Problem:")
                self.reportError( res )
        except:
            print(str(sys.exc_info()))
        return tickets

    def logUpload( self, photoID, imageName ):
        """ logUpload
        """

        photoID = str( photoID )
        imageName = str( imageName )
        self.uploaded[ imageName ] = photoID
        self.uploaded[ photoID ] = imageName

    def build_request(self, theurl, fields, files, txheaders=None):
        """
        build_request/encode_multipart_formdata code is from www.voidspace.org.uk/atlantibots/pythonutils.html

        Given the fields to set and the files to encode it returns a fully formed urllib2.Request object.
        You can optionally pass in additional headers to encode into the opject. (Content-type and Content-length will be overridden if they are set).
        fields is a sequence of (name, value) elements for regular form fields - or a dictionary.
        files is a sequence of (name, filename, value) elements for data to be uploaded as files.
        """

        content_type, body = self.encode_multipart_formdata(fields, files)
        if not txheaders: txheaders = {}
        txheaders['Content-type'] = content_type
        txheaders['Content-length'] = str(len(body))

        return urllib2.Request(theurl, body, txheaders)

    def encode_multipart_formdata(self,fields, files, BOUNDARY = '-----'+mimetools.choose_boundary()+'-----'):
        """ Encodes fields and files for uploading.
        fields is a sequence of (name, value) elements for regular form fields - or a dictionary.
        files is a sequence of (name, filename, value) elements for data to be uploaded as files.
        Return (content_type, body) ready for urllib2.Request instance
        You can optionally pass in a boundary string to use or we'll let mimetools provide one.
        """

        CRLF = '\r\n'
        L = []
        if isinstance(fields, dict):
            fields = fields.items()
        for (key, value) in fields:
            L.append('--' + BOUNDARY)
            L.append('Content-Disposition: form-data; name="%s"' % key)
            L.append('')
            L.append(value)
        for (key, filename, value) in files:
            filetype = mimetypes.guess_type(filename)[0] or 'application/octet-stream'
            L.append('--' + BOUNDARY)
            L.append('Content-Disposition: form-data; name="%s"; filename="%s"' % (key, filename))
            L.append('Content-Type: %s' % filetype)
            L.append('')
            L.append(value)
        L.append('--' + BOUNDARY + '--')
        L.append('')
        body = CRLF.join(L)
        content_type = 'multipart/form-data; boundary=%s' % BOUNDARY        # XXX what if no files are encoded
        return content_type, body


    def isGood( self, res ):
        """ isGood
        """

        if ( not res == "" and res('stat') == "ok" ):
            return True
        else :
            return False


    def reportError( self, res ):
        """ reportError
        """

        try:
            print("Error: " + str( res.err('code') + " " + res.err('msg') ))
        except:
            print("Error: " + str( res ))

    def getResponse( self, url ):
        """
        Send the url and get a response.  Let errors float up
        """

        xml = urllib2.urlopen( url ).read()
        return xmltramp.parse( xml )


    def run( self ):
        """ run
        """

        while ( True ):
            self.upload()
            print("Last check: " + str( time.asctime(time.localtime())))
            time.sleep( SLEEP_TIME )

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Upload images to Flickr.')
    parser.add_argument('-d', '--daemon', action='store_true',
        help='Run forever as a daemon')
    parser.add_argument('-i', '--title',       action='store',
        help='Title for uploaded images')
    parser.add_argument('-e', '--description', action='store',
        help='Description for uploaded images')
    parser.add_argument('-t', '--tags',        action='store',
        help='Space-separated tags for uploaded images')
    parser.add_argument('-s', '--sets',        action='store',
        help='Photo set ID to add the photo into')
    parser.add_argument('-r', '--drip-feed',   action='store_true',
        help='Wait a bit between uploading individual images')
    args = parser.parse_args()

    flick = Uploadr()

    if args.daemon:
        flick.run()
    else:
        flick.upload()
