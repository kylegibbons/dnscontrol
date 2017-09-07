"use strict";

var conf = {
    registrars: [],
    dns_providers: [],
    domains: []
};

var defaultArgs = [];

function initialize(){
    conf = {
        registrars: [],
        dns_providers: [],
        domains: []
    };
    defaultArgs = [];
}

function NewRegistrar(name,type,meta) {
    if (type) {
      type == "MANUAL";
    }
    var reg = {name: name, type: type, meta: meta};
    conf.registrars.push(reg);
    return name;
}

function NewDnsProvider(name, type, meta) {
    if  ((typeof meta === 'object') && ('ip_conversions' in meta)) {
        meta.ip_conversions = format_tt(meta.ip_conversions)
    }
    var dsp = {name: name, type: type, meta: meta};
    conf.dns_providers.push(dsp);
    return name;
}

function newDomain(name,registrar) {
    return {name: name, registrar: registrar, meta:{}, records:[], dnsProviders: {}, defaultTTL: 0, nameservers:[]};
}

function processDargs(m, domain) {
        // for each modifier, if it is a...
        // function: call it with domain
        // array: process recursively
        // object: merge it into metadata
        if (_.isFunction(m)) {
               m(domain);
        } else if (_.isArray(m)) {
            for (var j in m) {
              processDargs(m[j], domain)
            }
        } else if (_.isObject(m)) {
            _.extend(domain.meta,m);
        } else {
          throw "WARNING: domain modifier type unsupported: "+ typeof m + " Domain: "+ domain.name;
        }
}

// D(name,registrar): Create a DNS Domain. Use the parameters as records and mods.
function D(name,registrar) {
    var domain = newDomain(name,registrar);
    for (var i = 0; i< defaultArgs.length; i++){
       processDargs(defaultArgs[i],domain)
   }
    for (var i = 2; i<arguments.length; i++) {
        var m = arguments[i];
        processDargs(m, domain)
    }
   conf.domains.push(domain)
}

// DEFAULTS provides a set of default arguments to apply to all future domains.
// Each call to DEFAULTS will clear any previous values set.
function DEFAULTS(){
    defaultArgs = [];
    for (var i = 0; i<arguments.length; i++) {
        defaultArgs.push(arguments[i]);
    }
}

// TTL(v): Set the TTL for a DNS record.
function TTL(v) {
    if (_.isString(v)){
        v = stringToDuration(v);
    }
    return function(r) {
        r.ttl = v;
    }
}

function stringToDuration(v){
    var matches = v.match(/^(\d+)([smhdwny]?)$/);
    if (matches == null){
        throw v + " is not a valid duration string"
    }
    unit = "s"
    if (matches[2]){
        unit = matches[2]
    }
    v = parseInt(matches[1])
    var u = {"s":1, "m":60, "h":3600}
    u["d"] = u.h * 24
    u["w"] = u.d * 7
    u["n"] = u.d * 30
    u["y"] = u.d * 365
    v *= u[unit];
    return v
}

// DefaultTTL(v): Set the default TTL for the domain.
function DefaultTTL(v) {
    if (_.isString(v)){
        v = stringToDuration(v);
    }
    return function(d) {
        d.defaultTTL = v;
    }
}

function makeCAAFlag(value){
    return function(record){
        record.caaflag |= value;
    };
}

// CAA_CRITICAL: Critical CAA flag
var CAA_CRITICAL = makeCAAFlag(1<<0);


// DnsProvider("providerName", 0) 
// nsCount of 0 means don't use or register any nameservers.
// nsCount not provider means use all.
function DnsProvider(name, nsCount){
    if(typeof nsCount === 'undefined'){
        nsCount = -1;
    }
    return function(d) {
        d.dnsProviders[name] = nsCount;
    }
}

// A(name,ip, recordModifiers...)
var A = recordBuilder('A');

// AAAA(name,ip, recordModifiers...)
var AAAA = recordBuilder('AAAA');

// ALIAS(name,target, recordModifiers...)
var ALIAS = recordBuilder('ALIAS');

// CAA(name,tag,value, recordModifiers...)
var CAA = recordBuilder('CAA', {
    args: [
        ['name', _.isString],
        ['tag', _.isString],
        ['value', _.isString],
    ],
    transform: function(record, args, modifiers){
        record.name = args.name;
        record.caatag = args.tag;
        record.target = args.value;
    },
    modifierNumber: function(record, value){
        record.caaflags |= value;
    },
});

// CNAME(name,target, recordModifiers...)
var CNAME = recordBuilder('CNAME');

// PTR(name,target, recordModifiers...)
var PTR = recordBuilder('PTR');

// SRV(name,priority,weight,port,target, recordModifiers...)
var SRV = recordBuilder('SRV', {
    args: [
        ['name', _.isString],
        ['priority', _.isNumber],
        ['weight', _.isNumber],
        ['port', _.isNumber],
        ['target', _.isString],
    ],
    transform: function(record, args, modifiers){
        record.name = args.name;
        record.srvpriority = args.priority;
        record.srvweight = args.weight;
        record.srvport = args.port;
        record.target = args.target;
    },
});

// TXT(name,target, recordModifiers...)
var TXT = recordBuilder('TXT');

// MX(name,priority,target, recordModifiers...)
var MX = recordBuilder('MX', {
    args: [
        ['name', _.isString],
        ['priority', _.isNumber],
        ['target', _.isString],
    ],
    transform: function(record, args, modifiers){
        record.name = args.name;
        record.mxpreference = args.priority;
        record.target = args.target;
    },
});

function checkArgs(checks, args, desc){
    if (args.length < checks.length){
        throw(desc)
    }
    for (var i = 0; i< checks.length; i++){
        if (!checks[i](args[i])){
            throw(desc+" - argument "+i+" is not correct type")
        }
    }
}

// NS(name,target, recordModifiers...)
var NS = recordBuilder('NS');

// NAMESERVER(name,target)
function NAMESERVER(name, target) {
    return function(d) {
        d.nameservers.push({name: name, target: target})
    }
}

function format_tt(transform_table) {
  // Turn [[low: 1, high: 2, newBase: 3], [low: 4, high: 5, newIP: 6]]
  // into "1 ~ 2 ~ 3 ~; 4 ~ 5 ~  ~ 6"
  var lines = []
  for (var i=0; i < transform_table.length; i++) {
    var ip = transform_table[i];
    var newIP = ip.newIP;
    if (newIP){
        if(_.isArray(newIP)){
            newIP = _.map(newIP,function(i){return num2dot(i)}).join(",")
        }else{
            newIP = num2dot(newIP);
        }
    }
    var newBase = ip.newBase;
    if (newBase){
        if(_.isArray(newBase)){
            newBase = _.map(newBase,function(i){return num2dot(i)}).join(",")
        }else{
            newBase = num2dot(newBase);
        }
    }
    var row = [
      num2dot(ip.low),
      num2dot(ip.high),
      newBase,
      newIP
    ]
    lines.push(row.join(" ~ "))
  }
  return lines.join(" ; ")
}

// IMPORT_TRANSFORM(translation_table, domain)
var IMPORT_TRANSFORM = recordBuilder('IMPORT_TRANSFORM', {
    args: [
        ['translation_table'],
        ['domain'],
        ['ttl', _.isNumber],
    ],
    transform: function(record, args, modifiers){
        record.name = '@';
        record.target = args.domain;
        record.meta['transform_table'] = format_tt(args.translation_table);
        record.ttl = args.ttl;
    },
});

// PURGE()
function PURGE(d) {
  d.KeepUnknown = false
}

// NO_PURGE()
function NO_PURGE(d) {
  d.KeepUnknown = true
}

/**
 * @deprecated
 */
function getModifiers(args,start) {
    var mods = [];
    for (var i = start;i<args.length; i++) {
        mods.push(args[i])
    }
    return mods;
}

/**
 * Record type builder
 * @param {string} type Record type
 * @param {string} opts.args[][0] Argument name
 * @param {function=} opts.args[][1] Optional validator
 * @param {function=} opts.transform Function to apply arguments to record.
 *        Take (record, args, modifier) as arguments. Any modifiers will be
 *        applied before this function. It should mutate the given record.
 * @param {function=} opts.applyModifier Function to apply modifiers to the record
 */
function recordBuilder(type, opts){
    opts = _.defaults({}, opts, {
        args: [
            ['name', _.isString],
            ['target'],
        ],

        transform: function(record, args, modifiers) {
            // record will have modifiers already applied
            // args will be an object for parameters defined
            record.name = args.name;
            if (_.isNumber(args.target)) {
                record.target = num2dot(args.target);
            } else {
                record.target = args.target;
            }
        },

        applyModifier: function(record, modifiers) {
            for (var i = 0; i < modifiers.length; i++) {
                var mod = modifiers[i];

                if (_.isFunction(mod)) {
                    mod(record);
                } else if (_.isObject(mod)) {
                    // convert transforms to strings
                    if (mod.transform && _.isArray(mod.transform)) {
                        mod.transform = format_tt(mod.transform);
                    }
                    _.extend(record.meta, mod);
                } else {
                    throw "ERROR: Unknown modifier type";
                }
            }
        },
    });

    return function(){
        var parsedArgs = {};
        var modifiers = [];

        if (arguments.length < opts.args.length) {
            var argumentsList = opts.args.map(function(item){
                return item[0];
            }).join(', ');
            throw type + " record requires " + opts.args.length + " arguments (" + argumentsList + "). Only " + arguments.length + " were supplied";
            return;
        }

        // collect arguments
        for (var i = 0; i < opts.args.length; i++) {
            var argDefinition = opts.args[i];
            var value = arguments[i];
            if (argDefinition.length > 1) {
                // run validator if supplied
                if(!argDefinition[1](value)){
                    throw type + " record " + argDefinition[0] + " argument validation failed";
                }
            }
            parsedArgs[argDefinition[0]] = value;
        }

        // collect modifiers
        for (var i = opts.args.length; i < arguments.length; i++) {
            modifiers.push(arguments[i]);
        }

        return function(d){
            var record = {
                type: type,
                meta: {},
                ttl: d.defaultTTL,
            };

            opts.applyModifier(record, modifiers);
            opts.transform(record, parsedArgs, modifiers);

            d.records.push(record);
            return record;
        };
    };
}

/**
 * @deprecated
 */
function addRecord(d,type,name,target,mods) {
    // if target is number, assume ip address. convert it.
    if (_.isNumber(target)) {
        target = num2dot(target);
    }
    var rec = {type: type, name: name, target: target, ttl:d.defaultTTL, priority: 0, meta:{}};
    // for each modifier, decide based on type:
    // - Function: call is with the record as the argument
    // - Object: merge it into the metadata
    // - Number: IF MX record assume it is priority
    if (mods) {
        for (var i = 0; i< mods.length; i++) {
            var m = mods[i]
            if (_.isFunction(m)) {
                m(rec);
            } else if (_.isObject(m)) {
                 //convert transforms to strings
                 if (m.transform && _.isArray(m.transform)){
                    m.transform = format_tt(m.transform)
                 }
                _.extend(rec.meta,m);
                _.extend(rec.meta,m);
            } else {
                console.log("WARNING: Modifier type unsupported:", typeof m, "(Skipping!)");
            }
        }
    }
    d.records.push(rec);
    return rec;
}

//ip conversion functions from http://stackoverflow.com/a/8105740/121660
// via http://javascript.about.com/library/blipconvert.htm
function IP(dot)
{
    var d = dot.split('.');
    return ((((((+d[0])*256)+(+d[1]))*256)+(+d[2]))*256)+(+d[3]);
}

function num2dot(num)
{
    if(num === undefined){
        return "";
    }
    if (_.isString(num)){
        return num
    }
    var d = num%256;
    for (var i = 3; i > 0; i--)
    {
        num = Math.floor(num/256);
        d = num%256 + '.' + d;
    }
    return d;
}


// Cloudflare aliases:

// Meta settings for individual records.
var CF_PROXY_OFF = {'cloudflare_proxy': 'off'};     // Proxy disabled.
var CF_PROXY_ON = {'cloudflare_proxy': 'on'};       // Proxy enabled.
var CF_PROXY_FULL = {'cloudflare_proxy': 'full'};   // Proxy+Railgun enabled.
// Per-domain meta settings:
// Proxy default off for entire domain (the default):
var CF_PROXY_DEFAULT_OFF = {'cloudflare_proxy_default': 'off'};
// Proxy default on for entire domain:
var CF_PROXY_DEFAULT_ON = {'cloudflare_proxy_default': 'on'};

// CUSTOM, PROVIDER SPECIFIC RECORD TYPES

function _validateCloudFlareRedirect(value){
    if(!_.isString(value)){
        return false;
    }
    return value.indexOf(",") === -1;
}

var CF_REDIRECT = recordBuilder("CF_REDIRECT", {
    args: [
        ["source", _validateCloudFlareRedirect],
        ["destination", _validateCloudFlareRedirect],
    ],
    transform: function(record, args, modifiers){
        record.name = "@";
        record.target = args.source + "," + args.destination;
    },
});

var CF_TEMP_REDIRECT = recordBuilder("CF_TEMP_REDIRECT", {
    args: [
        ["source", _validateCloudFlareRedirect],
        ["destination", _validateCloudFlareRedirect],
    ],
    transform: function(record, args, modifiers){
        record.name = "@";
        record.target = args.source + "," + args.destination;
    },
});