# SAFE TEAM
#
#
# distributed under license: CC BY-NC-SA 4.0 (https://creativecommons.org/licenses/by-nc-sa/4.0/legalcode.txt) #
#实验  main函数在这里
import argparse
# from dataset_creation import DatabaseFactory, DataSplitter
import DatabaseFactory, DataSplitter
def debug_msg():
    msg =  " DATABASE UTILITY"
    msg += "-------------------------------------------------\n"
    msg += "This program is an utility to save data into an sqlite database with SAFE \n\n"  #效用utility
    msg += "There are three main command: \n"
    msg += "BUILD:  It create a db with two tables: functions, filtered_functions. \n"  ## filtered_functions 过滤函数
    msg += "        In the first table there are all the functions extracted from the executable with their hex code.\n" # 从可执行文件的16进制代码中提取所有函数
    msg += "        In the second table functions are converted to i2v representation. \n"  #函数被转化为了i2v形式				
    msg += "SPLIT:  Data are splitted into train validation and test set. "              #数据被分割成了数据，验证，测试集
    msg +=  "        Then it generate the pairs for the training of the network.\n"          #然后生成用于训练网络的对
    msg += "EMBEDD: Generate the embeddings of each function in the database using a trained SAFE model\n\n"  #嵌入：使用训练好的SAFG模型在数据库中生成每个函数的嵌入
    msg += "If you want to train the network use build + split"  					      #训练网络用 build+split
    msg += "If you want to create a knowledge base for the binary code search engine use build + embedd"	#用build + embedd 为二进制代码搜索引擎创建知识库
    msg += "This program has been written by the SAFE team.\n" 							#SAFE团队编写
    msg += "-------------------------------------------------"
    return msg


def build_configuration(db_name, root_dir, use_symbols):
    msg = "Database creation options: \n"
    msg += " - Database Name: {} \n".format(db_name)
    msg += " - Root dir: {} \n".format(root_dir)
    msg += " - Use symbols: {} \n".format(use_symbols)
    return msg


def split_configuration(db_name, val_split, test_split, epochs):
    msg = "Splitting options: \n"
    msg += " - Database Name: {} \n".format(db_name)
    msg += " - Validation Size: {} \n".format(val_split)
    msg += " - Test Size: {} \n".format(test_split)
    msg += " - Epochs: {} \n".format(epochs)
    return msg


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description=debug_msg)

    parser.add_argument("-db", "--db", help="Name of the database to create", required=True)  #创建的数据库名字

    parser.add_argument("-b", "--build", help="Build db disassebling executables",   action="store_true")  #建立数据库拆解可执行文件（SQL指令建立数据库？？？）
    parser.add_argument("-s", "--split", help="Perform data splitting for training", action="store_true") #为训练拆解数据

    parser.add_argument("-dir", "--dir",     help="Root path of the directory to scan") #要扫描的目录的根路径
    parser.add_argument("-sym", "--symbols", help="Use it if you want to use symbols", action="store_true", default=0) #如果想用符号，使用它  这里符号什么含义,
    # 在后面的分析中symbols=0的时候只是分析用户自定义的函数,为1的时候分析用户定义函数和系统。库函数

    parser.add_argument("-test", "--test_size", help="Test set size [0-1]",            type=float, default=0.2) #测试集大小
    parser.add_argument("-val",  "--val_size",  help="Validation set size [0-1]",      type=float, default=0.2) #验证集大小
    parser.add_argument("-epo",  "--epochs",    help="# Epochs to generate pairs for", type=int,    default=25) #生成成对的时期

    try:
        args = parser.parse_args()
    except:
        parser.print_help()
        print(debug_msg())
        exit(0)

    if args.build:
        print("Disassemblying files and creating dataset")
        print(build_configuration(args.db, args.dir, args.symbols))
        factory = DatabaseFactory.DatabaseFactory(args.db, args.dir)
        factory.build_db(args.symbols)

    if args.split:
        print("Splitting data and generating epoch pairs")
        print(split_configuration(args.db, args.val_size, args.test_size, args.epochs))
        splitter = DataSplitter.DataSplitter(args.db)
        splitter.split_data(args.val_size, args.test_size)
        splitter.create_pairs(args.epochs)

    exit(0)
