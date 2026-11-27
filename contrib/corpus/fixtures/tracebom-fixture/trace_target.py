import yaml

document = "fixture: true"
parsed = yaml.safe_load(document)
print("tracebom fixture parsed:", parsed)
