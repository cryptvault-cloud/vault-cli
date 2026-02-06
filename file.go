package main

import (
	"fmt"
	"os"
	"path"
	"strings"
)

type FileHandling interface {
	Init() error
	SaveTextToFile(filePath string, content string) error
	ReadTextFile(filePath string) (string, error)
	AvailableVaults() ([]string, error)
	SelectedVault() (string, error)
	DeleteFolder(filePath string) error
	FullPath(filePath string) string
}

type FileHandlerMock struct {
}

func (f *FileHandlerMock) FullPath(filePath string) string {
	return filePath
}

func (f *FileHandlerMock) Init() error {
	return nil
}
func (f *FileHandlerMock) SaveTextToFile(filePath string, content string) error {
	return nil
}
func (f *FileHandlerMock) ReadTextFile(filePath string) (string, error) {
	return "", fmt.Errorf("not found")
}

func (f *FileHandlerMock) AvailableVaults() ([]string, error) {
	return []string{}, nil
}
func (f *FileHandlerMock) SelectedVault() (string, error) {
	return "", fmt.Errorf("not found")
}

func (f *FileHandlerMock) DeleteFolder(filePath string) error {
	return nil
}

type FileHandler struct {
	RootPath string
}

func (f *FileHandler) SelectedVault() (string, error) {
	return f.ReadTextFile("/currentVault.txt")
}

func (f *FileHandler) Init() error {
	if _, err := os.Stat(f.RootPath); os.IsNotExist(err) {
		return os.MkdirAll(f.RootPath, 0700)
	} else {
		return nil
	}
}

func (f *FileHandler) FullPath(filePath string) string {
	if strings.Contains(path.Clean(filePath), path.Clean(f.RootPath)) {
		return filePath
	}
	return path.Join(f.RootPath, filePath)
}

func (f *FileHandler) DeleteFolder(filePath string) error {
	return os.RemoveAll(f.FullPath(filePath))
}

func (f *FileHandler) SaveTextToFile(filePath string, content string) error {
	p := f.FullPath(filePath)
	folders := path.Dir(p)
	err := os.MkdirAll(folders, 0700)
	if err != nil {
		return err
	}
	return os.WriteFile(p, []byte(content), 0600)
}

func (f *FileHandler) ReadTextFile(filePath string) (string, error) {
	res, err := os.ReadFile(f.FullPath(filePath))
	if err != nil {
		return "", err
	}
	return string(res), nil
}

func (f *FileHandler) AvailableVaults() ([]string, error) {
	dirs, err := os.ReadDir(f.RootPath)
	if err != nil {
		return nil, err
	}
	result := make([]string, 0)
	for _, v := range dirs {
		if v.IsDir() {
			result = append(result, v.Name())
		}
	}
	return result, nil
}
