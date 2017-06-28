# -*- coding: utf-8 -*-
from south.utils import datetime_utils as datetime
from south.db import db
from south.v2 import SchemaMigration
from django.db import models


class Migration(SchemaMigration):
    """Initial Migration for Defender"""

    def forwards(self, orm):
        """ Adding model 'AccessAttempt' """
        db.create_table(u'defender_accessattempt', (
            (u'id', self.gf('django.db.models.fields.AutoField')(primary_key=True)),
            ('user_agent', self.gf('django.db.models.fields.CharField')(max_length=255)),
            ('ip_address', self.gf('django.db.models.fields.GenericIPAddressField')(max_length=39, null=True)),
            ('username', self.gf('django.db.models.fields.CharField')(max_length=255, null=True)),
            ('http_accept', self.gf('django.db.models.fields.CharField')(max_length=1025)),
            ('path_info', self.gf('django.db.models.fields.CharField')(max_length=255)),
            ('attempt_time', self.gf('django.db.models.fields.DateTimeField')(auto_now_add=True, blank=True)),
            ('login_valid', self.gf('django.db.models.fields.BooleanField')(default=False)),
        ))
        db.send_create_signal(u'defender', ['AccessAttempt'])


    def backwards(self, orm):
        # Deleting model 'AccessAttempt'
        db.delete_table(u'defender_accessattempt')


    models = {
        u'defender.accessattempt': {
            'Meta': {'ordering': "[u'-attempt_time']", 'object_name': 'AccessAttempt'},
            'attempt_time': ('django.db.models.fields.DateTimeField', [], {'auto_now_add': 'True', 'blank': 'True'}),
            'http_accept': ('django.db.models.fields.CharField', [], {'max_length': '1025'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'ip_address': ('django.db.models.fields.GenericIPAddressField', [], {'max_length': '39', 'null': 'True'}),
            'login_valid': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'path_info': ('django.db.models.fields.CharField', [], {'max_length': '255'}),
            'user_agent': ('django.db.models.fields.CharField', [], {'max_length': '255'}),
            'username': ('django.db.models.fields.CharField', [], {'max_length': '255', 'null': 'True'})
        }
    }

    complete_apps = ['defender']
