#!/bin/sh

test_description='Test command line plugin for RFC 46 job shape'

. $(dirname $0)/sharness.sh

export FLUX_CLI_PLUGINPATH=${FLUX_SOURCE_DIR}/src/bindings/python/flux/cli/plugins/

test_under_flux 4 job

test_expect_success 'flux-alloc: a job that does not provide a job shape can run' '
	flux alloc -N4 flux resource list -no {nnodes} | grep 4 
'
test_expect_success 'flux-run: job that calls shape plugin has resources set properly' '
	cat <<-EOF > exp1.json &&
	[
	  {
	    "type": "slot",
	    "count": 4,
	    "label": "task",
	    "with": [
	      {
	        "type": "node",
	        "count": 1
	      }
	    ]
	  }
	]
	EOF
	flux run --shape=slot=4/node --dry-run hostname | jq .resources >  output1.json &&
	diff -s exp1.json output1.json | grep "Files exp1.json and output1.json are identical"
'

test_expect_success 'flux-submit: job with invalid shape is rejected' '
	test_must_fail flux alloc --shape=slot/ echo hello 2> err.out &&
	grep "flux-alloc: ERROR" err.out
'

test_expect_success 'flux-batch: subinstance job with shape plugin has proper resources' '
	cat <<-EOF > exp2.json &&
	[
	  {
	    "type": "node",
	    "count": 1,
	    "with": [
	      {
	        "type": "slot",
	        "count": 10,
	        "label": "read-db",
	        "with": [
	          {
	            "type": "core",
	            "count": 1
	          },
	          {
	            "type": "memory",
	            "count": 4,
	            "unit": "GB"
	          }
	        ]
	      },
	      {
	        "type": "slot",
	        "count": 1,
	        "label": "db",
	        "with": [
	          {
	            "type": "core",
	            "count": 6
	          },
	          {
	            "type": "memory",
	            "count": 24,
	            "unit": "GB"
	          }
	        ]
	      }
	    ]
	  }
	]
	EOF
	flux batch --shape=node/[slot=10{read-db}/[core\;memory=4{unit:GB}]\;slot{db}/[core=6\;memory=24{unit:GB}]] \
    --dry-run --wrap hostname | jq .resources > output2.json && 
  diff -s exp2.json output2.json | grep "Files exp2.json and output2.json are identical"
'
test_done
