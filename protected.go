package main

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"os"
	"path"
	"regexp"
	"strings"

	client "github.com/cryptvault-cloud/api"
	"github.com/cryptvault-cloud/helper"
	"github.com/urfave/cli/v3"
)

type ProtectedRunner struct {
	runner     *Runner
	api        client.ProtectedApiHandler
	privateKey *ecdsa.PrivateKey
	vaultId    *string
}

type ValueType string

const (
	ValueTypeString ValueType = "String"
	ValueTypeJSON   ValueType = "JSON"
)

var AllValueType = []ValueType{
	ValueTypeString,
	ValueTypeJSON,
}

var ValuePatternRegex *regexp.Regexp

func init() {
	ValuePatternRegex = regexp.MustCompile(helper.ValuePatternRegexStr)
}

func GetProtectedCommand(runner *Runner) *cli.Command {

	pRunner := &ProtectedRunner{runner: runner}
	return &cli.Command{
		Name:   "protected",
		Usage:  "All stuff where you need a private key and a vault id to handle",
		Before: pRunner.Before,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     CliProtectedHandlerKey,
				Aliases:  []string{"creds"},
				Sources:  cli.EnvVars(getFlagEnvByFlagName(CliProtectedHandlerKey)),
				Usage:    "Private key wich have rights to handle subcommand or path to private key ",
				Required: true,
			},
			&cli.StringFlag{
				Name:    CliProtectedVaultId,
				Sources: cli.EnvVars(getFlagEnvByFlagName(CliProtectedVaultId)),
				Usage:   "vaultid to handle subcommand",
			},
		},
		Commands: []*cli.Command{
			{
				Name:  "add",
				Usage: "add new value or identity",
				Commands: []*cli.Command{
					{
						Name:   "identity",
						Usage:  "add a new identity",
						Action: pRunner.AddIdentity,
						Flags: []cli.Flag{
							&cli.StringFlag{
								Name:     CliAddIdentityName,
								Sources:  cli.EnvVars(getFlagEnvByFlagName(CliAddIdentityName)),
								Usage:    "Name of identity",
								Required: true,
							},
							&cli.StringFlag{
								Name:     CliAddIdentityPublicKey,
								Sources:  cli.EnvVars(getFlagEnvByFlagName(CliAddIdentityPublicKey)),
								Usage:    "If set, no new key pair will created, it will use this public key as identity base",
								Value:    "",
								Required: false,
							},
							&cli.StringSliceFlag{
								Name:    CliAddIdentityRights,
								Aliases: []string{"r"},
								Sources: cli.EnvVars(getFlagEnvByFlagName(CliAddIdentityRights)),
								Usage:   "Rights for the new identity",
								Action: func(ctx context.Context, c *cli.Command, s []string) error {
									var err error = nil
									for _, one := range s {
										if !ValuePatternRegex.Match([]byte(one)) {
											err = errors.Join(fmt.Errorf("Have to match right string pattern: %s", helper.ValuePatternRegexStr))
										}
									}
									return err
								},
								Required: true,
							},
						},
					},
					{
						Name:  "value",
						Usage: "add a new value if value already exists it will be overwritten",
						Flags: []cli.Flag{
							&cli.StringFlag{
								Name:    CliAddValueName,
								Sources: cli.EnvVars(getFlagEnvByFlagName(CliAddValueName)),
								Usage:   "Key of value",
							},
							&cli.StringFlag{
								Name:    CliAddValuePassframe,
								Sources: cli.EnvVars(getFlagEnvByFlagName(CliAddValuePassframe)),
								Usage:   "Password of value",
							},
							&cli.StringFlag{
								Name:    CliAddValueType,
								Sources: cli.EnvVars(getFlagEnvByFlagName(CliAddValueType)),
								Usage:   "type of value String or JSON",
								Value:   "String",
							},
						},
						Action: pRunner.AddValue,
					},
				},
			},
			{
				Name:  "get",
				Usage: "Get Secrets, Identity",
				Commands: []*cli.Command{
					{
						Name:   "identity",
						Usage:  "returns information over identity ",
						Action: pRunner.GetIdentity,
						Flags: []cli.Flag{
							&cli.StringFlag{
								Name:     CliGetIdentityId,
								Sources:  cli.EnvVars(getFlagEnvByFlagName(CliGetIdentityId)),
								Usage:    "IdentityId to looking for",
								Required: true,
							},
						},
					},
					{
						Name:   "value",
						Usage:  "returns the secret",
						Action: pRunner.GetValue,
						Flags: []cli.Flag{
							&cli.StringFlag{
								Name:     CliGetValueName,
								Sources:  cli.EnvVars(getFlagEnvByFlagName(CliGetValueName)),
								Usage:    "Value name something like VALUES.a.b",
								Required: true,
							},
						},
					},
				},
			},
			{
				Name:    "ls",
				Aliases: []string{"list"},
				Usage:   "List multiple information creds identity",
				Commands: []*cli.Command{
					{
						Name:   "values",
						Usage:  "show all keys of all related values",
						Action: pRunner.ListRelatedValues,
					},
					{
						Name:   "identities",
						Usage:  "show all identities",
						Action: pRunner.ListAllIdentities,
					},
				},
			},
			{
				Name:  "update",
				Usage: "Update Secrets, Identities",
				Commands: []*cli.Command{
					{
						Name:   "value",
						Usage:  "update a value and set new secret",
						Action: pRunner.UpdateValue,
						Flags: []cli.Flag{
							&cli.StringFlag{
								Name:     CliUpdateValueName,
								Sources:  cli.EnvVars(getFlagEnvByFlagName(CliUpdateValueName)),
								Usage:    "Key of value",
								Required: true,
							},
							&cli.StringFlag{
								Name:     CliUpdateValuePassframe,
								Sources:  cli.EnvVars(getFlagEnvByFlagName(CliUpdateValuePassframe)),
								Usage:    "Password of value",
								Required: true,
							},
							&cli.StringFlag{
								Name:    CliUpdateValueType,
								Sources: cli.EnvVars(getFlagEnvByFlagName(CliUpdateValueType)),
								Usage:   "type of value String or JSON",
								Value:   "String",
							},
						},
					},
					{
						Name:   "identity",
						Usage:  "update a identity",
						Action: pRunner.UpdateIdentity,
						Flags: []cli.Flag{
							&cli.StringFlag{
								Name:     CliUpdateIdentityId,
								Sources:  cli.EnvVars(getFlagEnvByFlagName(CliUpdateIdentityId)),
								Usage:    "id of identity",
								Required: true,
							},
							&cli.StringFlag{
								Name:    CliUpdateIdentityName,
								Sources: cli.EnvVars(getFlagEnvByFlagName(CliUpdateIdentityName)),
								Usage:   "Name of identity",
							},
							&cli.StringSliceFlag{
								Name:    CliUpdateIdentityRightsAdd,
								Aliases: []string{"ra"},
								Sources: cli.EnvVars(getFlagEnvByFlagName(CliUpdateIdentityRightsAdd)),
								Usage:   "Rights for the identity to add",
								Action: func(ctx context.Context, c *cli.Command, s []string) error {
									var err error = nil
									for _, one := range s {
										if !ValuePatternRegex.Match([]byte(one)) {
											err = errors.Join(fmt.Errorf("Have to match right string pattern: %s", helper.ValuePatternRegexStr))
										}
									}
									return err
								},
							},
							&cli.StringSliceFlag{
								Name:    CliUpdateIdentityRightsRemove,
								Aliases: []string{"rd"},
								Sources: cli.EnvVars(getFlagEnvByFlagName(CliUpdateIdentityRightsRemove)),
								Usage:   "Rights for the identity to remove",
								Action: func(ctx context.Context, c *cli.Command, s []string) error {
									var err error = nil
									for _, one := range s {
										if !ValuePatternRegex.Match([]byte(one)) {
											err = errors.Join(fmt.Errorf("Have to match right string pattern: %s", helper.ValuePatternRegexStr))
										}
									}
									return err
								},
							},
						},
					},
				},
			},
			{
				Name:  "delete",
				Usage: "Get Secrets, Identity",
				Commands: []*cli.Command{
					{
						Name:   "vault",
						Usage:  "Delete an empty vault",
						Action: pRunner.DeleteVault,
					},
					{
						Name:   "identity",
						Usage:  "Delete an identity",
						Action: pRunner.DeleteIdentity,
						Flags: []cli.Flag{
							&cli.StringFlag{
								Name:     CliDeleteIdentityId,
								Sources:  cli.EnvVars(getFlagEnvByFlagName(CliDeleteIdentityId)),
								Usage:    "ID of identity",
								Required: true,
							},
						},
					},
					{
						Name:   "value",
						Usage:  "Delete an value",
						Action: pRunner.DeleteValue,
						Flags: []cli.Flag{
							&cli.StringFlag{
								Name:     CliDeleteValueName,
								Sources:  cli.EnvVars(getFlagEnvByFlagName(CliDeleteValueName)),
								Usage:    "Name of value to delete",
								Required: true,
							},
						},
					},
				},
			},
			{
				Name:   "authToken",
				Usage:  "Generate JWT-Authtoken",
				Action: pRunner.GenerateAuthToken,
			},
		},
	}
}

func (r *ProtectedRunner) Before(ctx context.Context, c *cli.Command) (context.Context, error) {
	pemKeyOrPath := c.String(CliProtectedHandlerKey)
	pemKey := ""
	if _, err := os.Stat(pemKeyOrPath); errors.Is(err, os.ErrNotExist) {
		// path does not exist so it have to be private key directly
		pemKey = pemKeyOrPath
	} else {
		t, err := r.runner.fileHandler.ReadTextFile(pemKeyOrPath)
		if err != nil {
			return ctx, err
		}
		pemKey = t
	}
	privKey, err := helper.GetPrivateKeyFromB64String(pemKey)
	if err != nil {
		return ctx, err
	}
	vaultId := c.String(CliProtectedVaultId)
	if vaultId == "" {
		vault, err := r.runner.fileHandler.SelectedVault()
		if err != nil {
			return ctx, err
		}
		vaultId, err = r.runner.fileHandler.ReadTextFile(fmt.Sprintf("%s/vaultId", vault))
		if err != nil {
			return ctx, err
		}
	}
	r.privateKey = privKey
	r.vaultId = &vaultId

	r.api = r.runner.api.GetProtectedApi(privKey, vaultId)
	return ctx, nil
}
func (r *ProtectedRunner) ListAllIdentities(ctx context.Context, c *cli.Command) error {

	identityResult, err := r.api.GetAllIdentities()
	if err != nil {
		return err
	}
	identities := identityResult.QueryIdentity.Data
	for _, identity := range identities {
		fmt.Printf("%s\n", *identity.Name)
		for _, right := range identity.Rights {
			fmt.Printf("\t(%s)%s\n", right.Right[:1], right.RightValuePattern)
		}
	}
	return nil
}

func (r *ProtectedRunner) ListRelatedValues(ctx context.Context, c *cli.Command) error {
	b64pub, err := helper.NewBase64PublicPem(&r.privateKey.PublicKey)
	if err != nil {
		return err
	}
	identityId, err := b64pub.GetIdentityId(*r.vaultId)
	if err != nil {
		return err
	}
	values, err := r.api.GetAllRelatedValues(identityId)
	if err != nil {
		return err
	}
	if len(values) == 0 {
		fmt.Println("No Values related for this identity")
	} else {
		fmt.Println("Related valuekeys:")
		for _, v := range values {
			fmt.Println(v.Name)
		}
	}
	return nil
}
func (r *ProtectedRunner) AddValue(ctx context.Context, c *cli.Command) error {
	valueType := c.String(CliAddValueType)
	if !helper.Includes(AllValueType, func(v ValueType) bool { return valueType == string(v) }) {
		return fmt.Errorf("not allowed Type")
	}
	_, err := r.api.AddValue(c.String(CliAddValueName), c.String(CliAddValuePassframe), client.ValueType(valueType))
	if err != nil {
		return err
	}

	fmt.Printf("Value %s was created \n", c.String(CliAddValueName))
	return nil
}

func (r *ProtectedRunner) UpdateValue(ctx context.Context, c *cli.Command) error {
	valueType := c.String(CliAddValueType)
	if !helper.Includes(AllValueType, func(v ValueType) bool { return valueType == string(v) }) {
		return fmt.Errorf("not allowed Type")
	}
	value, err := r.api.GetValueByName(c.String(CliUpdateValueName))
	if err != nil {
		return err
	}

	_, err = r.api.UpdateValue(value.Id, value.Name, c.String(CliUpdateValuePassframe), client.ValueType(c.String(CliUpdateValueType)))
	if err != nil {
		return err
	}
	fmt.Printf("%s was updated\n", value.Name)
	return nil
}

func getRightInputs(rights []string) ([]*client.RightInput, error) {
	rightInputs := make([]*client.RightInput, 0)
	var errs error = nil
	for _, v := range rights {
		tmp, err := client.GetRightDescriptionByString(v)
		if err != nil {
			errs = errors.Join(errs, fmt.Errorf("error by right %s :%w", v, err))
			continue
		}
		for _, tmpV := range tmp {
			rightInputs = append(rightInputs, &client.RightInput{
				Target:            tmpV.Target,
				Right:             tmpV.Right,
				RightValuePattern: tmpV.RightValue,
			})
		}
	}
	return rightInputs, errs
}

func (r *ProtectedRunner) UpdateIdentity(ctx context.Context, c *cli.Command) error {
	rightsAdd := c.StringSlice(CliUpdateIdentityRightsAdd)
	rightsRemove := c.StringSlice(CliUpdateIdentityRightsRemove)
	name := c.String(CliUpdateIdentityName)
	id := c.String(CliUpdateIdentityId)
	identity, err := r.api.GetIdentity(id)
	if err != nil {
		return err
	}

	rightStr := make([]string, 0, len(identity.Rights))
	for _, r := range identity.Rights {

		rightStr = append(rightStr, fmt.Sprintf("(%s)%s", r.Right[:1], r.RightValuePattern))
	}
	currentRights, err := getRightInputs(rightStr)
	if err != nil {
		return err
	}

	if name != "" {
		identity.Name = &name
	}

	if len(rightsRemove) > 0 {
		removeRights, err := getRightInputs(rightsRemove)
		if err != nil {
			return err
		}
		for _, r := range removeRights {
			r := r
			containsRight := helper.Contains(currentRights, r, func(value, toCheck *client.RightInput) bool {
				return fmt.Sprintf("(%s)%s", value.Right[:1], value.RightValuePattern) == fmt.Sprintf("(%s)%s", toCheck.Right[:1], toCheck.RightValuePattern)
			})
			if !containsRight {
				return fmt.Errorf("Right to remove %s was not found at current identity rights", fmt.Sprintf("(%s)%s", r.Right[:1], r.RightValuePattern))
			} else {
				currentRights = helper.Filter(currentRights, func(value *client.RightInput) bool {
					return fmt.Sprintf("(%s)%s", value.Right[:1], value.RightValuePattern) != fmt.Sprintf("(%s)%s", r.Right[:1], r.RightValuePattern)
				})
			}
		}
	}
	if len(rightsAdd) > 0 {
		addRights, err := getRightInputs(rightsAdd)
		if err != nil {
			return err
		}
		for _, r := range addRights {
			r := r
			containsRight := helper.Contains(currentRights, r, func(value, toCheck *client.RightInput) bool {
				return fmt.Sprintf("(%s)%s", value.Right, value.RightValuePattern) == fmt.Sprintf("(%s)%s", toCheck.Right, toCheck.RightValuePattern)
			})
			if !containsRight {
				currentRights = append(currentRights, r)
			}
		}
	}

	oldValues, err := r.api.GetAllRelatedValuesWithIdentityValues(id)
	if err != nil {
		return err
	}
	var errorList error = nil
	for _, v := range oldValues {
		for _, vv := range v.Value {
			if vv.IdentityID == id {
				_, err := r.api.DeleteIdentityValue(&vv.Id)
				errorList = errors.Join(errorList, err)
			}
		}

	}
	if errorList != nil {
		return errorList
	}

	_, err = r.api.UpdateIdentity(id, *identity.Name, currentRights)
	if err != nil {
		return err
	}

	values, err := r.api.GetAllRelatedValues(id)
	if err != nil {
		return err
	}
	for _, v := range values {
		err := r.api.SyncValue(v.Id)
		if err != nil {
			return err
		}
	}

	fmt.Printf("Identity updated\n")
	return nil
}

func (r *ProtectedRunner) AddIdentity(ctx context.Context, c *cli.Command) error {
	rights := c.StringSlice(CliAddIdentityRights)
	name := c.String(CliAddIdentityName)
	b64pubKey := c.String(CliAddIdentityPublicKey)

	rightInputs, err := getRightInputs(rights)
	if err != nil {
		return err
	}
	if b64pubKey == "" {
		// create a new KeyPair
		res, err := r.api.CreateIdentity(name, rightInputs)
		if err != nil {
			return err
		}
		err = r.api.SyncValues(res.IdentityId)
		if err != nil {
			return err
		}

		vaultName, err := r.runner.fileHandler.SelectedVault()
		if err != nil {
			return err
		}
		b64PubKey, err := helper.GetB64FromPublicKey(res.PublicKey)
		if err != nil {
			return err
		}
		b64PrivKey, err := helper.GetB64FromPrivateKey(res.PrivateKey)
		if err != nil {
			return err
		}

		err = errors.Join(r.runner.fileHandler.SaveTextToFile(fmt.Sprintf("%s/identity/%s/key.pub", vaultName, name), b64PubKey), err)
		err = errors.Join(r.runner.fileHandler.SaveTextToFile(fmt.Sprintf("%s/identity/%s/key", vaultName, name), b64PrivKey), err)
		err = errors.Join(r.runner.fileHandler.SaveTextToFile(fmt.Sprintf("%s/identity/%s/id", vaultName, name), res.IdentityId), err)
		if err != nil {
			return err
		}
		fmt.Print("Identity was created \n")
		fmt.Printf("Identity information was saved at %s\n", path.Join(c.String(CliSaveFilePath), vaultName, "identity", name))
		return nil
	} else {

		// add identity by given public key
		pubKey, err := helper.GetPublicKeyFromB64String(b64pubKey)
		if err != nil {
			return err
		}

		_, err = r.api.AddIdentity(name, pubKey, rightInputs)
		if err != nil {
			return err
		}
		fmt.Print("Identity was created\nNo Information will be saved locally...")
		return nil
	}

}

func (r *ProtectedRunner) GetIdentity(ctx context.Context, c *cli.Command) error {
	id := c.String(CliGetIdentityId)
	res, err := r.api.GetIdentity(id)
	if err != nil {
		return err
	}

	rigthstr := make([]string, len(res.Rights))

	for i, v := range res.Rights {
		rigthstr[i] = fmt.Sprintf("(%s)%s", v.Right[:1], v.RightValuePattern)
	}

	fmt.Printf("ID: %s\nName: %s\nRights: \n\t%s\n", res.Id, *res.Name, strings.Join(rigthstr, "\n\t"))
	return nil
}

func (r *ProtectedRunner) GetValue(ctx context.Context, c *cli.Command) error {
	name := c.String(CliGetValueName)
	value, err := r.api.GetValueByName(name)
	if err != nil {
		return err
	}
	values := make([]client.EncryptenValue, 0)
	for _, v := range value.GetValue() {
		values = append(values, v)
	}
	passframe, err := r.api.GetDecryptedPassframe(values)
	if err != nil {
		return err
	}
	fmt.Println(passframe)
	return nil
}

func (r *ProtectedRunner) GenerateAuthToken(ctx context.Context, c *cli.Command) error {
	jwt, err := helper.SignJWT(r.privateKey, *r.vaultId)
	if err != nil {
		return err
	}
	fmt.Println(jwt)
	return nil
}

func (r *ProtectedRunner) DeleteVault(ctx context.Context, c *cli.Command) error {

	err := r.api.DeleteVault(*r.vaultId)
	if err != nil {
		return err
	}
	fmt.Println("Vault Deleted")
	return nil

}

func (r *ProtectedRunner) DeleteIdentity(ctx context.Context, c *cli.Command) error {
	vaultName, err := r.runner.fileHandler.SelectedVault()
	if err != nil {
		return err
	}

	identityIdToDelete := c.String(CliDeleteIdentityId)
	res, err := r.api.GetIdentity(identityIdToDelete)
	if err != nil {
		return err
	}
	err = r.api.DeleteIdentity(identityIdToDelete)
	if err != nil {
		return err
	}
	err = r.runner.fileHandler.DeleteFolder(fmt.Sprintf("%s/identity/%s", vaultName, *res.Name))
	if err != nil {
		return err
	}
	fmt.Println("Identity Deleted")
	return nil
}

func (r *ProtectedRunner) DeleteValue(ctx context.Context, c *cli.Command) error {
	nameOfValue2Delete := c.String(CliDeleteValueName)
	value, err := r.api.GetValueByName(nameOfValue2Delete)
	if err != nil {
		return err
	}
	err = r.api.DeleteValue(value.Id)
	if err != nil {
		return err
	}
	fmt.Println("Value deleted")
	return nil
}
