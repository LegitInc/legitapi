# Copyright (C) 2013  Rob Boyle / Legit Inc
# 
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see http://www.gnu.org/licenses

from google.appengine.ext import ndb
import models

class Mapper(object):
    KIND = None
    FILTERS = []

    def map(self, entity):
        return ([],[])

    def get_query(self):
        q = self.KIND.query()
        for prop, value in self.FILTERS:
            q = q.filter("%s = " % prop, value)
        return q

    def run(self):
        q = self.get_query()
        to_put = []
        to_delete_keys = []
        for entity in q:
            map_updates, map_delete_keys = self.map(entity)
            to_put.extend(map_updates)
            to_delete_keys.extend(map_delete_keys)
        if to_put:
            print "Updating %d entities" % len(to_put)
            ndb.put_multi(to_put)
        if to_delete_keys:
            print "Deleting %d entities" % len(to_delete_keys)
            ndb.delete_multi(to_delete_keys)
            
class IntakeUserTestMapper(Mapper):
    KIND = models.IntakeUser
    
    def map(self, entity):
        print entity.key
        return ([],[])
        
class IntakeUserSetAPIMapper(Mapper):
    KIND = models.IntakeUser

    def __init__(self, api_type):
        self.api_type = api_type
    
    def map(self, entity):
        to_put = []
        to_delete = []
        if entity.api_type != self.api_type:
            entity.api_type = self.api_type
            to_put.append(entity)
        return (to_put, to_delete)
            
            
        
            
            